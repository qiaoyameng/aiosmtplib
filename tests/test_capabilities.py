"""
Capability snapshot and observer behavior.
"""

import dataclasses
from typing import Any

import pytest

from aiosmtplib import SMTP, CapabilitySnapshot, SMTPHeloError, SMTPStatus

from .smtpd import mock_response_ehlo_fail_on_reconnect, mock_response_ehlo_phases


@pytest.mark.smtpd_options(tls=False)
@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_phases)
async def test_capability_snapshot_phases_and_generations(smtp_client: SMTP) -> None:
    notifications: list[CapabilitySnapshot | None] = []
    smtp_client.add_capability_observer(notifications.append)

    await smtp_client.connect()
    assert smtp_client.capability_snapshot is None

    await smtp_client.ehlo()
    cleartext_snapshot = smtp_client.capability_snapshot
    assert cleartext_snapshot is not None
    assert cleartext_snapshot.phase == "cleartext"
    assert cleartext_snapshot.generation == 1
    assert cleartext_snapshot.extensions["size"] == "1000"
    assert cleartext_snapshot.auth_methods == ("login",)
    assert cleartext_snapshot.supports("STARTTLS")

    # STARTTLS invalidates the old capabilities immediately
    await smtp_client.starttls()
    assert smtp_client.capability_snapshot is None
    assert notifications[-1] is None

    # The next snapshot is only published once the new EHLO completes
    await smtp_client.ehlo()
    tls_snapshot = smtp_client.capability_snapshot
    assert tls_snapshot is not None
    assert tls_snapshot.phase == "tls"
    assert tls_snapshot.generation == 2
    assert tls_snapshot.extensions["size"] == "2000"
    assert tls_snapshot.auth_methods == ("plain", "login")
    assert not tls_snapshot.supports("starttls")

    await smtp_client.quit()
    assert smtp_client.capability_snapshot is None

    # Reconnecting starts a new generation with fresh capabilities
    await smtp_client.connect()
    await smtp_client.ehlo()
    reconnected_snapshot = smtp_client.capability_snapshot
    assert reconnected_snapshot is not None
    assert reconnected_snapshot.phase == "cleartext"
    assert reconnected_snapshot.generation == 3
    assert reconnected_snapshot.extensions["size"] == "3000"
    assert reconnected_snapshot.auth_methods == ("plain",)

    await smtp_client.quit()

    published = [n for n in notifications if n is not None]
    invalidated = [n for n in notifications if n is None]
    assert published == [cleartext_snapshot, tls_snapshot, reconnected_snapshot]
    assert len(invalidated) == 3


@pytest.mark.smtpd_options(tls=False)
@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_phases)
async def test_capability_snapshot_is_immutable(smtp_client: SMTP) -> None:
    async with smtp_client:
        await smtp_client.ehlo()
        snapshot = smtp_client.capability_snapshot
        assert snapshot is not None

        with pytest.raises(TypeError):
            snapshot.extensions["chunking"] = ""  # type: ignore[index]
        with pytest.raises(dataclasses.FrozenInstanceError):
            snapshot.generation = 99  # type: ignore[misc]

        # The client's internal state is unaffected
        assert "chunking" not in smtp_client.esmtp_extensions
        assert smtp_client.capability_snapshot is snapshot


@pytest.mark.smtpd_options(tls=False)
@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_phases)
async def test_capability_observer_drives_send_options(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    selected_options: list[list[str]] = []

    def select_options(snapshot: CapabilitySnapshot | None) -> None:
        if snapshot is not None and snapshot.supports("8bitmime"):
            selected_options.append(["BODY=8BITMIME"])
        else:
            selected_options.append([])

    smtp_client.add_capability_observer(select_options)

    async def send_with_selected_options() -> None:
        await smtp_client.sendmail(
            "sender@example.com",
            ["rcpt@example.com"],
            "hello",
            mail_options=selected_options[-1],
        )

    def mail_options_sent() -> list[list[str]]:
        return [
            list(args[1]) for command, args in received_commands if command == "MAIL"
        ]

    await smtp_client.connect()
    await smtp_client.ehlo()

    # Cleartext generation: no 8BITMIME, so the selector adds no options
    await send_with_selected_options()
    assert mail_options_sent() == [["SIZE=5"]]
    assert smtp_client.server_auth_methods == ["login"]

    # TLS generation: 8BITMIME appears, and the selector adjusts
    await smtp_client.starttls()
    await smtp_client.ehlo()
    await send_with_selected_options()
    assert mail_options_sent()[-1] == ["SIZE=5", "BODY=8BITMIME"]
    assert smtp_client.server_auth_methods == ["plain", "login"]

    # Reconnect generation: capabilities change again
    await smtp_client.quit()
    await smtp_client.connect()
    await smtp_client.ehlo()
    await send_with_selected_options()
    assert mail_options_sent()[-1] == ["SIZE=5"]
    assert smtp_client.server_auth_methods == ["plain"]

    await smtp_client.quit()


@pytest.mark.smtpd_options(tls=False)
@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_ehlo_fail_on_reconnect)
async def test_failed_negotiation_does_not_reuse_previous_capabilities(
    smtp_client: SMTP,
) -> None:
    notifications: list[CapabilitySnapshot | None] = []
    smtp_client.add_capability_observer(notifications.append)

    await smtp_client.connect()
    response = await smtp_client.ehlo()
    assert response.code == SMTPStatus.completed
    assert smtp_client.supports_extension("size")
    first_snapshot = smtp_client.capability_snapshot
    assert first_snapshot is not None

    await smtp_client.quit()

    await smtp_client.connect()
    with pytest.raises(SMTPHeloError):
        await smtp_client.ehlo()

    # The failed negotiation must not fall back to the old capabilities
    assert smtp_client.capability_snapshot is None
    assert not smtp_client.supports_extension("size")
    assert notifications[-1] is None

    await smtp_client.quit()


async def test_remove_capability_observer(smtp_client: SMTP) -> None:
    notifications: list[CapabilitySnapshot | None] = []
    smtp_client.add_capability_observer(notifications.append)
    smtp_client.remove_capability_observer(notifications.append)

    async with smtp_client:
        await smtp_client.ehlo()

    assert notifications == []
    assert smtp_client.capability_snapshot is not None
