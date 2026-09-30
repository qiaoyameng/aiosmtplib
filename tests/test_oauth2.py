"""
Integration tests for XOAUTH2 authentication with an async token generator,
against a scripted local SMTP server.
"""

import asyncio
import base64
import json
import socket
from collections.abc import AsyncGenerator, Awaitable, Callable

import pytest
import pytest_asyncio

from aiosmtplib import SMTP, SMTPAuthenticationError


def _json_challenge(status: str) -> str:
    error = {"status": status, "schemes": "bearer", "scope": "https://example.com/"}
    return base64.b64encode(json.dumps(error).encode("utf-8")).decode("ascii")


EXPIRED_TOKEN_CHALLENGE = _json_challenge("401")
FORBIDDEN_CHALLENGE = _json_challenge("403")

AUTH_FAILED_RESPONSE = "535 5.7.8 Username and Password not accepted"
AUTH_SUCCESS_RESPONSE = "235 2.7.0 Accepted"


class XOAuth2Server:
    """
    A minimal scripted SMTP server speaking just enough ESMTP to test XOAUTH2.

    ``rounds`` holds one (challenges, final response) tuple per expected
    AUTH XOAUTH2 command. Each challenge is sent as a 334 reply, and the
    client must answer with an empty line before the next challenge or the
    final response is sent.
    """

    def __init__(self) -> None:
        self.rounds: list[tuple[list[str], str]] = []
        self.auth_commands: list[str] = []
        self.challenge_replies: list[bytes] = []

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 localhost ESMTP\r\n")
        await writer.drain()
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                command = line.decode("ascii", errors="replace").strip()
                if command.upper().startswith(("EHLO", "HELO")):
                    writer.write(b"250-localhost\r\n250 AUTH XOAUTH2\r\n")
                    await writer.drain()
                elif command.upper().startswith("AUTH XOAUTH2"):
                    self.auth_commands.append(command)
                    await self._run_auth_round(reader, writer)
                elif command.upper().startswith("QUIT"):
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")
                    await writer.drain()
        finally:
            writer.close()

    async def _run_auth_round(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if not self.rounds:
            writer.write(b"500 5.5.2 Unexpected AUTH command\r\n")
            await writer.drain()
            return
        challenges, final_response = self.rounds.pop(0)
        for challenge in challenges:
            writer.write(f"334 {challenge}\r\n".encode("ascii"))
            await writer.drain()
            self.challenge_replies.append(await reader.readline())
        writer.write(final_response.encode("ascii") + b"\r\n")
        await writer.drain()


class XOAuth2Peer:
    """Pairs an XOAuth2Server with SMTP clients over connected sockets."""

    def __init__(self) -> None:
        self.server = XOAuth2Server()
        self._server_tasks: list[asyncio.Task[None]] = []

    def make_client(
        self,
        *,
        username: str,
        oauth_token_generator: Callable[[], Awaitable[str]],
    ) -> SMTP:
        client_sock, server_sock = socket.socketpair()
        self._server_tasks.append(asyncio.create_task(self._run(server_sock)))
        return SMTP(
            sock=client_sock,
            username=username,
            oauth_token_generator=oauth_token_generator,
        )

    async def _run(self, sock: socket.socket) -> None:
        reader, writer = await asyncio.open_connection(sock=sock)
        await self.server.handle_client(reader, writer)

    async def close(self) -> None:
        for task in self._server_tasks:
            task.cancel()
        for task in self._server_tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


@pytest_asyncio.fixture(scope="function")
async def xoauth2_peer() -> AsyncGenerator[XOAuth2Peer]:
    peer = XOAuth2Peer()
    yield peer
    await peer.close()


def _token_from_auth_command(command: str) -> str:
    encoded = command.split(" ", 2)[2]
    decoded = base64.b64decode(encoded).decode("utf-8")
    return decoded.split("\x01auth=Bearer ")[1].rstrip("\x01")


def _make_token_generator(
    tokens: list[str],
) -> tuple[Callable[[], Awaitable[str]], list[int]]:
    calls: list[int] = []

    async def get_token() -> str:
        calls.append(1)
        return tokens[len(calls) - 1]

    return get_token, calls


async def test_expired_token_is_refreshed_and_retried(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """An expired token (401 challenge) is refreshed once, then auth succeeds."""
    xoauth2_peer.server.rounds = [
        ([EXPIRED_TOKEN_CHALLENGE], AUTH_FAILED_RESPONSE),
        ([], AUTH_SUCCESS_RESPONSE),
    ]
    get_token, calls = _make_token_generator(["expired-token", "fresh-token"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    async with client:
        assert client.is_connected

    server = xoauth2_peer.server
    assert len(calls) == 2
    assert len(server.auth_commands) == 2
    assert _token_from_auth_command(server.auth_commands[0]) == "expired-token"
    assert _token_from_auth_command(server.auth_commands[1]) == "fresh-token"
    # The SASL exchange was terminated with an empty response before retrying
    assert server.challenge_replies == [b"\r\n"]


async def test_insufficient_permissions_not_refreshed(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """A 403 error challenge means bad permissions, not a stale token."""
    xoauth2_peer.server.rounds = [([FORBIDDEN_CHALLENGE], AUTH_FAILED_RESPONSE)]
    get_token, calls = _make_token_generator(["token-one", "token-two"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.connect()

    assert excinfo.value.code == 535
    assert len(calls) == 1
    assert len(xoauth2_peer.server.auth_commands) == 1


async def test_multiple_error_challenges_completed_before_retry(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """Every 334 challenge gets an empty reply before the client retries."""
    xoauth2_peer.server.rounds = [
        ([EXPIRED_TOKEN_CHALLENGE, EXPIRED_TOKEN_CHALLENGE], AUTH_FAILED_RESPONSE),
        ([], AUTH_SUCCESS_RESPONSE),
    ]
    get_token, calls = _make_token_generator(["expired-token", "fresh-token"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    async with client:
        assert client.is_connected

    assert len(calls) == 2
    assert xoauth2_peer.server.challenge_replies == [b"\r\n", b"\r\n"]
    assert len(xoauth2_peer.server.auth_commands) == 2


async def test_refresh_is_attempted_only_once(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """If the refreshed token is also rejected, no further refresh happens."""
    xoauth2_peer.server.rounds = [
        ([EXPIRED_TOKEN_CHALLENGE], AUTH_FAILED_RESPONSE),
        ([EXPIRED_TOKEN_CHALLENGE], AUTH_FAILED_RESPONSE),
    ]
    get_token, calls = _make_token_generator(["token-one", "token-two", "token-three"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    with pytest.raises(SMTPAuthenticationError):
        await client.connect()

    assert len(calls) == 2
    assert len(xoauth2_peer.server.auth_commands) == 2


async def test_refresh_failure_propagates(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """If the token generator fails while refreshing, its error propagates."""
    xoauth2_peer.server.rounds = [([EXPIRED_TOKEN_CHALLENGE], AUTH_FAILED_RESPONSE)]
    calls = 0

    async def failing_token_generator() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "expired-token"
        raise RuntimeError("token service unavailable")

    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=failing_token_generator
    )

    with pytest.raises(RuntimeError, match="token service unavailable"):
        await client.connect()

    assert calls == 2
    assert len(xoauth2_peer.server.auth_commands) == 1


async def test_transient_failure_not_refreshed(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """A transient 4xx server error never triggers a token refresh."""
    xoauth2_peer.server.rounds = [([], "451 4.7.0 Temporary local problem")]
    get_token, calls = _make_token_generator(["token-one", "token-two"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.connect()

    assert excinfo.value.code == 451
    assert len(calls) == 1
    assert len(xoauth2_peer.server.auth_commands) == 1


async def test_malformed_challenge_not_refreshed(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """An unparseable error challenge is a protocol error, not a stale token."""
    xoauth2_peer.server.rounds = [(["not-valid-base64!!!"], AUTH_FAILED_RESPONSE)]
    get_token, calls = _make_token_generator(["token-one", "token-two"])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    with pytest.raises(SMTPAuthenticationError):
        await client.connect()

    assert len(calls) == 1
    assert len(xoauth2_peer.server.auth_commands) == 1


async def test_token_not_in_exception(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """Tokens must never appear in exceptions raised to the caller."""
    secret_token = "super-secret-token-12345"
    xoauth2_peer.server.rounds = [([FORBIDDEN_CHALLENGE], AUTH_FAILED_RESPONSE)]
    get_token, _ = _make_token_generator([secret_token])
    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=get_token
    )

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await client.connect()

    assert secret_token not in str(excinfo.value)
    assert secret_token not in repr(excinfo.value)
    assert all(secret_token not in str(arg) for arg in excinfo.value.args)


async def test_cancellation_during_token_fetch_stops_login(
    xoauth2_peer: XOAuth2Peer,
) -> None:
    """Cancelling the connect must not continue logging in afterwards."""
    token_fetch_started = asyncio.Event()

    async def hanging_token_generator() -> str:
        token_fetch_started.set()
        await asyncio.Event().wait()  # hangs until cancelled
        raise AssertionError("unreachable")

    client = xoauth2_peer.make_client(
        username="user@example.com", oauth_token_generator=hanging_token_generator
    )

    connect_task = asyncio.create_task(client.connect())
    await asyncio.wait_for(token_fetch_started.wait(), 1.0)
    connect_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await connect_task

    assert xoauth2_peer.server.auth_commands == []
    assert not client.is_connected
