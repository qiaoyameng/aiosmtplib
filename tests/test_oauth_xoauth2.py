"""
End-to-end style tests for refresh-aware XOAUTH2 authentication, driven
through the real SMTP client against a scripted in-process SMTP peer.
"""

import asyncio
import logging

import pytest

from aiosmtplib import SMTP
from aiosmtplib.auth import auth_xoauth2_encode
from aiosmtplib.errors import (
    SMTPAuthenticationError,
    SMTPResponseException,
    SMTPServerDisconnected,
)
from aiosmtplib.typing import SMTPStatus

from .oauth_peer import (
    FakeTokenProvider,
    XOAUTH2Peer,
    connect_smtp_with_peer,
)

USERNAME = "user@example.com"
EXPIRED_TOKEN = "expired-token-12345"
FRESH_TOKEN = "fresh-token-67890"
SCOPED_TOKEN = "wrong-scope-token"


def make_client() -> SMTP:
    return SMTP(timeout=1.0, local_hostname="memory-peer")


async def test_expired_token_refreshes_once_and_reauthenticates() -> None:
    peer = XOAUTH2Peer([("401", str(SMTPStatus.auth_failed)), "235"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN, FRESH_TOKEN])

    response = await client.login_xoauth2(USERNAME, provider)

    assert response.code == SMTPStatus.auth_successful
    # The provider is awaited before each exchange: one initial + one refresh.
    assert provider.calls == 2
    assert provider.returned == [EXPIRED_TOKEN, FRESH_TOKEN]
    # Two complete SASL exchanges were attempted.
    assert peer.auth_attempts == 2
    assert peer.tokens == [EXPIRED_TOKEN, FRESH_TOKEN]
    # The failed challenge exchange was terminated with an empty line before
    # the retry AUTH was sent.
    assert peer.empty_challenge_responses == 1
    assert b"AUTH XOAUTH2 " + auth_xoauth2_encode(
        USERNAME, EXPIRED_TOKEN
    ) in peer.commands
    assert b"AUTH XOAUTH2 " + auth_xoauth2_encode(
        USERNAME, FRESH_TOKEN
    ) in peer.commands


async def test_insufficient_scope_does_not_refresh() -> None:
    peer = XOAUTH2Peer([("403", str(SMTPStatus.auth_failed))])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([SCOPED_TOKEN])

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.login_xoauth2(USERNAME, provider)

    assert excinfo.value.code == SMTPStatus.auth_failed
    assert excinfo.value.xoauth2_error == "403"
    # Only the initial fetch: a scope error can't be fixed by a new token.
    assert provider.calls == 1
    assert provider.returned == [SCOPED_TOKEN]
    assert peer.auth_attempts == 1
    assert peer.empty_challenge_responses == 1


async def test_refresh_fetch_happens_after_sasl_exchange_finished() -> None:
    """
    The fresh token must not be requested until the failed SASL exchange has
    been fully terminated (empty-line challenge response sent and the final
    reply read).
    """
    peer = XOAUTH2Peer([("401", "535"), "235"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)

    snapshots: list[tuple[int, int]] = []

    async def provider() -> str:
        snapshots.append(
            (peer.auth_attempts, peer.empty_challenge_responses)
        )
        return EXPIRED_TOKEN if len(snapshots) == 1 else FRESH_TOKEN

    await client.login_xoauth2(USERNAME, provider)

    # Initial fetch precedes the first AUTH; the refresh fetch happens only
    # after the empty line terminated that exchange.
    assert snapshots == [(0, 0), (1, 1)]


async def test_multiple_error_challenges_retried_only_once() -> None:
    """
    The refreshed token is also rejected with a refreshable 401 challenge.
    We must end that second SASL exchange too, then give up - a third token
    fetch and a third login are never attempted.
    """
    peer = XOAUTH2Peer(
        [("401", str(SMTPStatus.auth_failed)), ("401", "535")]
    )
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN, FRESH_TOKEN])

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.login_xoauth2(USERNAME, provider)

    assert excinfo.value.code == SMTPStatus.auth_failed
    assert excinfo.value.xoauth2_error == "401"
    # Exactly one refresh: initial fetch + one retry fetch, never a third.
    assert provider.calls == 2
    assert peer.auth_attempts == 2
    assert peer.tokens == [EXPIRED_TOKEN, FRESH_TOKEN]
    # Both SASL exchanges were properly terminated by empty lines.
    assert peer.empty_challenge_responses == 2
    auth_commands = [c for c in peer.commands if c.startswith(b"AUTH XOAUTH2")]
    assert auth_commands == [
        b"AUTH XOAUTH2 " + auth_xoauth2_encode(USERNAME, EXPIRED_TOKEN),
        b"AUTH XOAUTH2 " + auth_xoauth2_encode(USERNAME, FRESH_TOKEN),
    ]


async def test_refresh_provider_failure_is_propagated_without_retry() -> None:
    """
    A refreshable 401 failure triggers a refresh, but the provider itself
    raises. That exception must surface to the caller, and no second AUTH
    command may be sent on the connection.
    """
    peer = XOAUTH2Peer([("401", str(SMTPStatus.auth_failed))])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN, RuntimeError("refresh failed")])

    with pytest.raises(RuntimeError, match="refresh failed"):
        await client.login_xoauth2(USERNAME, provider)

    assert provider.calls == 2
    # The first (failed) exchange happened; the provider error prevents any
    # second AUTH command.
    assert peer.auth_attempts == 1
    assert peer.empty_challenge_responses == 1
    assert len([c for c in peer.commands if c.startswith(b"AUTH XOAUTH2")]) == 1


@pytest.mark.parametrize(
    "outcome",
    ["451", "421"],
    ids=["transient_451", "service_shutdown_421"],
)
async def test_transient_service_failure_does_not_refresh(
    outcome: str,
) -> None:
    peer = XOAUTH2Peer([outcome])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN])

    with pytest.raises(SMTPResponseException):
        await client.login_xoauth2(USERNAME, provider)

    assert provider.calls == 1
    assert peer.auth_attempts == 1
    # No error challenge, so no empty-line SASL completion is involved.
    assert peer.empty_challenge_responses == 0


async def test_protocol_error_does_not_refresh() -> None:
    """A malformed reply is a protocol error, not a credential failure."""
    peer = XOAUTH2Peer(["gibberish"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN])

    with pytest.raises(SMTPResponseException):
        await client.login_xoauth2(USERNAME, provider)

    assert provider.calls == 1
    assert peer.auth_attempts == 1


async def test_disconnect_during_exchange_does_not_refresh() -> None:
    peer = XOAUTH2Peer(["disconnect"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN])

    with pytest.raises(SMTPServerDisconnected):
        await client.login_xoauth2(USERNAME, provider)

    assert provider.calls == 1
    assert peer.auth_attempts == 1


async def test_bare_auth_failure_without_challenge_does_not_refresh() -> None:
    """A plain 535 with no XOAUTH2 challenge is not a refreshable 401."""
    peer = XOAUTH2Peer(["535"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN])

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.login_xoauth2(USERNAME, provider)

    assert excinfo.value.xoauth2_error is None
    assert provider.calls == 1
    assert peer.auth_attempts == 1
    assert peer.empty_challenge_responses == 0


async def test_connect_path_refreshes_expired_token() -> None:
    """
    The ``oauth_token_generator`` configured on the client goes through the
    same one-shot refresh path during connect.
    """
    peer = XOAUTH2Peer([("401", "535"), "235"])
    client = SMTP(
        timeout=1.0,
        local_hostname="memory-peer",
        username=USERNAME,
        oauth_token_generator=FakeTokenProvider([EXPIRED_TOKEN, FRESH_TOKEN]),
    )
    await connect_smtp_with_peer(client, peer)

    await client._ehlo_or_helo_if_needed()
    await client._maybe_login_on_connect()

    assert peer.auth_attempts == 2
    assert peer.empty_challenge_responses == 1
    await client.quit()


async def test_cancellation_during_first_exchange_does_not_relogin() -> None:
    """
    If the first AUTH attempt is cancelled while waiting for its reply, no
    refresh fetch or second login may happen.
    """
    peer = XOAUTH2Peer(["235"])
    gate = asyncio.Event()
    peer.response_gate = gate
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN, FRESH_TOKEN])

    task = asyncio.ensure_future(client.login_xoauth2(USERNAME, provider))
    # Wait until the AUTH command is in flight and the reply is gated, then
    # cancel while the client is waiting for that reply.
    await peer.auth_received.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    gate.set()

    assert provider.calls == 1
    assert peer.auth_attempts == 1
    assert peer.empty_challenge_responses == 0


async def test_cancellation_during_refresh_does_not_relogin() -> None:
    """
    After a refreshable 401, cancellation while awaiting the fresh token must
    not be swallowed into a hidden re-login.
    """

    refresh_started = asyncio.Event()

    class CancellingProvider(FakeTokenProvider):
        async def __call__(self) -> str:
            self.calls += 1
            if self.calls == 2:
                refresh_started.set()
                await asyncio.Event().wait()
            return EXPIRED_TOKEN

    peer = XOAUTH2Peer([("401", "535"), "235"])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = CancellingProvider([])

    task = asyncio.ensure_future(client.login_xoauth2(USERNAME, provider))
    # Cancel only once the refresh fetch is actually in progress.
    await refresh_started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert provider.calls == 2
    assert peer.auth_attempts == 1
    assert peer.empty_challenge_responses == 1
    auth_commands = [
        c for c in peer.commands if c.startswith(b"AUTH XOAUTH2")
    ]
    assert len(auth_commands) == 1


async def test_token_never_in_exception_or_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    peer = XOAUTH2Peer([("401", "535"), ("401", "535")])
    client = make_client()
    await connect_smtp_with_peer(client, peer)
    provider = FakeTokenProvider([EXPIRED_TOKEN, FRESH_TOKEN])

    with caplog.at_level(logging.DEBUG, logger="aiosmtplib"):
        with pytest.raises(SMTPAuthenticationError) as excinfo:
            await client.login_xoauth2(USERNAME, provider)

    rendered = str(excinfo.value)
    assert EXPIRED_TOKEN not in rendered
    assert repr(excinfo.value) and EXPIRED_TOKEN not in repr(excinfo.value)
    for record in caplog.records:
        assert EXPIRED_TOKEN not in record.getMessage()
