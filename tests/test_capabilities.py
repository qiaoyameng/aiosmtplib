"""
Capability snapshots, observers and extension selectors.
"""

import dataclasses
from typing import Any

import pytest
from aiosmtpd.smtp import SMTP as SMTPD

from aiosmtplib import SMTP, CapabilitySnapshot, SMTPServerDisconnected

from .smtpd import mock_response_unrecognized_command


_cleartext_ehlo_count = 0


def _reset_ehlo_count() -> None:
    global _cleartext_ehlo_count
    _cleartext_ehlo_count = 0


async def mock_response_ehlo_generations(
    smtpd: SMTPD, *args: Any, **kwargs: Any
) -> None:
    """
    Advertise different capabilities for cleartext, TLS and reconnected
    sessions.
    """
    global _cleartext_ehlo_count
    if args and args[0]:
        smtpd.session.host_name = args[0]

    if smtpd._tls_protocol:
        await smtpd.push("250-localhost\n250-AUTH PLAIN\n250-SIZE 2000\n250 SMTPUTF8")
    else:
        _cleartext_ehlo_count += 1
        if _cleartext_ehlo_count == 1:
            await smtpd.push("250-localhost\n250-SIZE 1000\n250 STARTTLS")
        else:
            await smtpd.push("250-localhost\n250-SIZE 3000\n250 8BITMIME")


async def mock_response_ehlo_disconnect_on_reconnect(
    smtpd: SMTPD, *args: Any, **kwargs: Any
) -> None:
    """
    Answer EHLO normally on the first connection, then drop the connection.
    """
    global _cleartext_ehlo_count
    _cleartext_ehlo_count += 1
    if _cleartext_ehlo_count > 1:
        smtpd.transport.close()
        return

    if args and args[0]:
        smtpd.session.host_name = args[0]
    await smtpd.push("250-localhost\n250 SIZE 1000")


@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_generations)
async def test_capability_snapshots_track_phases_and_generations(
    smtp_client: SMTP,
    sender_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    _reset_ehlo_count()
    events: list[CapabilitySnapshot | None] = []
    smtp_client.add_capabilities_observer(events.append)

    def smtputf8_selector(snapshot: CapabilitySnapshot | None) -> list[str]:
        if snapshot is not None and snapshot.supports_extension("smtputf8"):
            return ["SMTPUTF8"]
        return []

    smtp_client.add_extension_selector(smtputf8_selector)

    await smtp_client.connect()
    assert smtp_client.capabilities is None

    # Cleartext capabilities, published after the first EHLO
    await smtp_client.mail(sender_str)
    cleartext_snapshot = smtp_client.capabilities
    assert cleartext_snapshot is not None
    assert cleartext_snapshot.phase == "cleartext"
    assert cleartext_snapshot.generation == 1
    assert cleartext_snapshot.extensions == {"size": "1000", "starttls": ""}
    assert received_commands[-1][1][1] == []

    # STARTTLS invalidates the old capabilities immediately
    await smtp_client.starttls()
    assert smtp_client.capabilities is None

    # New capabilities are published only after the next EHLO completes
    await smtp_client.mail(sender_str)
    tls_snapshot = smtp_client.capabilities
    assert tls_snapshot is not None
    assert tls_snapshot.phase == "tls"
    assert tls_snapshot.generation == 1
    assert tls_snapshot.auth_methods == ("plain",)
    assert tls_snapshot.extensions == {
        "auth": "PLAIN",
        "size": "2000",
        "smtputf8": "",
    }
    assert received_commands[-1][1][1] == ["SMTPUTF8"]

    # Reconnecting enters a new generation
    await smtp_client.quit()
    assert smtp_client.capabilities is None
    await smtp_client.connect()
    await smtp_client.mail(sender_str)
    reconnect_snapshot = smtp_client.capabilities
    assert reconnect_snapshot is not None
    assert reconnect_snapshot.phase == "cleartext"
    assert reconnect_snapshot.generation == 2
    assert reconnect_snapshot.extensions == {"size": "3000", "8bitmime": ""}
    assert received_commands[-1][1][1] == []

    assert events == [
        cleartext_snapshot,
        None,
        tls_snapshot,
        None,
        reconnect_snapshot,
    ]

    smtp_client.close()


async def test_capability_snapshot_is_immutable(smtp_client: SMTP) -> None:
    async with smtp_client:
        await smtp_client.ehlo()

        snapshot = smtp_client.capabilities
        assert snapshot is not None
        assert dict(snapshot.extensions) == smtp_client.esmtp_extensions
        assert tuple(snapshot.auth_methods) == tuple(smtp_client.server_auth_methods)

        with pytest.raises(TypeError):
            snapshot.extensions["size"] = "1"
        with pytest.raises(dataclasses.FrozenInstanceError):
            snapshot.generation = 99  # type: ignore[misc]

        # Failed mutations must not leak into the client's state
        assert smtp_client.esmtp_extensions.get("size") != "1"
        assert smtp_client.capabilities is snapshot


async def test_capabilities_observer_registration(smtp_client: SMTP) -> None:
    events: list[CapabilitySnapshot | None] = []
    smtp_client.add_capabilities_observer(events.append)
    smtp_client.add_capabilities_observer(events.append)

    async with smtp_client:
        await smtp_client.ehlo()
        assert events == [smtp_client.capabilities]

        smtp_client.remove_capabilities_observer(events.append)
        await smtp_client.rset()

    assert len(events) == 1

    with pytest.raises(ValueError):
        smtp_client.remove_capabilities_observer(events.append)


async def test_extension_selector_registration(
    smtp_client: SMTP,
    sender_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    def selector(snapshot: CapabilitySnapshot | None) -> list[str]:
        return ["X-SELECTED"]

    smtp_client.add_extension_selector(selector)
    smtp_client.add_extension_selector(selector)

    async with smtp_client:
        await smtp_client.mail(sender_str)
        assert received_commands[-1][1][1] == ["X-SELECTED"]

        smtp_client.remove_extension_selector(selector)
        await smtp_client.mail(sender_str)
        assert received_commands[-1][1][1] == []

    with pytest.raises(ValueError):
        smtp_client.remove_extension_selector(selector)


@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_unrecognized_command)
async def test_extension_selector_receives_none_without_esmtp(
    smtp_client: SMTP,
    sender_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    seen: list[CapabilitySnapshot | None] = []

    def selector(snapshot: CapabilitySnapshot | None) -> list[str]:
        seen.append(snapshot)
        return ["X-FALLBACK"]

    smtp_client.add_extension_selector(selector)

    async with smtp_client:
        await smtp_client.mail(sender_str)

    # EHLO failed and HELO was used, so no snapshot was published
    assert seen == [None]
    assert smtp_client.capabilities is None
    assert received_commands[-1][1][1] == ["X-FALLBACK"]


@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_disconnect_on_reconnect)
async def test_failed_negotiation_does_not_reuse_previous_capabilities(
    smtp_client: SMTP,
) -> None:
    _reset_ehlo_count()

    await smtp_client.connect()
    await smtp_client.ehlo()
    assert smtp_client.capabilities is not None
    await smtp_client.quit()

    # On reconnect the server drops us during EHLO; the previous
    # connection's capabilities must not be reused.
    await smtp_client.connect()
    with pytest.raises(SMTPServerDisconnected):
        await smtp_client.ehlo()

    assert smtp_client.capabilities is None
    assert not smtp_client.supports_extension("size")

    smtp_client.close()
