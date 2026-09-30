"""
Socket-free tests proving send_message follows the pre-send plan.
"""

from email.message import EmailMessage

import pytest

from aiosmtplib import SMTP
from aiosmtplib.errors import SMTPNotSupported
from aiosmtplib.response import SMTPResponse
from aiosmtplib.typing import SMTPStatus


class FakeTransport:
    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass


class FakeProtocol:
    """Record commands and answer every SMTP command with 250 OK."""

    def __init__(self) -> None:
        self.commands: list[tuple[bytes, ...]] = []
        self.data_payloads: list[bytes] = []
        self.is_connected = True
        self.transport = FakeTransport()

    async def execute_command(
        self, *args: bytes, timeout: float | None = None
    ) -> SMTPResponse:
        self.commands.append(args)
        return SMTPResponse(SMTPStatus.completed, "OK")

    async def execute_data_command(
        self, message: bytes, timeout: float | None = None
    ) -> SMTPResponse:
        self.commands.append((b"DATA",))
        self.data_payloads.append(message)
        return SMTPResponse(SMTPStatus.completed, "Message accepted")


def make_client(extensions: dict[str, str] | None = None) -> tuple[SMTP, FakeProtocol]:
    client = SMTP()
    protocol = FakeProtocol()
    client.protocol = protocol  # type: ignore[assignment]
    client.transport = protocol.transport  # type: ignore[assignment]
    client.supports_esmtp = True
    client.esmtp_extensions = extensions or {}
    # Skip the EHLO round trip; extensions are set above.
    client.last_helo_response = SMTPResponse(SMTPStatus.completed, "localhost")
    return client, protocol


def make_message(sender: str = "alice@example.com", to: str = "bob@example.org",
                 body: str = "Hello") -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = "Test"
    message.set_content(body)
    return message


def command_arguments(
    commands: list[tuple[bytes, ...]], name: bytes
) -> tuple[bytes, ...]:
    for command in commands:
        if command[0] == name:
            return command[1:]
    raise AssertionError(f"No {name!r} command sent; commands: {commands}")


async def test_prepare_message_chinese_display_name_needs_no_smtputf8() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message(sender="张伟 <alice@example.com>", to="李四 <bob@example.org>")

    plan, options, flat = await client.prepare_message(message)

    assert plan.utf8_required is False
    assert "SMTPUTF8" not in [option.upper() for option in options]
    assert "BODY=8BITMIME" in [option.upper() for option in options]
    assert flat.isascii()
    assert b"=?utf-8?" in flat
    assert protocol.commands == []


async def test_send_message_chinese_display_name_is_mime_encoded() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message(sender="张伟 <alice@example.com>", to="李四 <bob@example.org>")

    errors, _ = await client.send_message(message)

    assert errors == {}
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == b"FROM:<alice@example.com>"
    assert b"SMTPUTF8" not in mail_args
    rcpt_args = command_arguments(protocol.commands, b"RCPT")
    assert rcpt_args[0] == b"TO:<bob@example.org>"
    assert protocol.data_payloads[0].isascii()


async def test_send_message_idn_domain_downgrades_envelope_and_headers() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message(sender="user@例え.jp", to="bob@example.org")

    errors, _ = await client.send_message(message)

    assert errors == {}
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == b"FROM:<user@xn--r8jz45g.jp>"
    assert b"SMTPUTF8" not in mail_args
    assert b"user@xn--r8jz45g.jp" in protocol.data_payloads[0]
    assert protocol.data_payloads[0].isascii()


async def test_send_message_idn_domain_uses_u_labels_with_smtputf8() -> None:
    client, protocol = make_client(
        extensions={"smtputf8": "", "8bitmime": ""}
    )
    message = make_message(sender="user@例え.jp", to="bob@example.org")

    errors, _ = await client.send_message(message)

    assert errors == {}
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == "FROM:<user@例え.jp>".encode("utf-8")
    assert b"SMTPUTF8" in mail_args
    assert "user@例え.jp".encode("utf-8") in protocol.data_payloads[0]


async def test_non_ascii_local_part_fails_before_mail_without_smtputf8() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message(sender="张伟@example.com", to="bob@example.org")

    with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
        await client.prepare_message(message)

    with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
        await client.send_message(message)

    assert protocol.commands == []


async def test_non_ascii_local_part_sends_with_smtputf8() -> None:
    client, protocol = make_client(
        extensions={"smtputf8": "", "8bitmime": ""}
    )
    message = make_message(sender="张伟@example.com", to="bob@example.org")

    errors, _ = await client.send_message(message)

    assert errors == {}
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == "FROM:<张伟@example.com>".encode("utf-8")
    assert b"SMTPUTF8" in mail_args
    assert "张伟@example.com".encode("utf-8") in protocol.data_payloads[0]


async def test_pure_ascii_envelope_sends_without_extensions() -> None:
    client, protocol = make_client(extensions={})
    message = make_message()

    errors, _ = await client.send_message(message)

    assert errors == {}
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == b"FROM:<alice@example.com>"
    assert mail_args == (b"FROM:<alice@example.com>",)
    rcpt_args = command_arguments(protocol.commands, b"RCPT")
    assert rcpt_args == (b"TO:<bob@example.org>",)
    assert protocol.data_payloads[0].isascii()


async def test_eight_bit_body_downgrades_to_seven_bit_without_8bitmime() -> None:
    client, protocol = make_client(extensions={})
    message = make_message(body="中文正文")

    plan, options, flat = await client.prepare_message(message)

    assert plan.body_8bit is True
    assert "BODY=8BITMIME" not in [option.upper() for option in options]
    assert flat.isascii()

    errors, _ = await client.send_message(message)
    assert errors == {}
    assert protocol.data_payloads[0].isascii()


async def test_prepare_and_send_use_the_same_plan() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message(sender="user@例え.jp", to="bob@example.org")

    plan, options, flat = await client.prepare_message(message)
    envelope_sender, envelope_recipients = plan.envelope(smtputf8=False)
    await client.sendmail(
        envelope_sender, envelope_recipients, flat, mail_options=options
    )

    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert mail_args[0] == b"FROM:<user@xn--r8jz45g.jp>"


async def test_explicit_smtputf8_option_requires_server_support() -> None:
    client, _protocol = make_client(extensions={"8bitmime": ""})
    message = make_message()

    with pytest.raises(SMTPNotSupported):
        await client.prepare_message(message, mail_options=["SMTPUTF8"])


async def test_reply_to_idn_header_downgrades_without_smtputf8() -> None:
    client, protocol = make_client(extensions={"8bitmime": ""})
    message = make_message()
    message["Reply-To"] = "reply@例え.jp"

    errors, _ = await client.send_message(message)

    assert errors == {}
    payload = protocol.data_payloads[0]
    assert b"reply@xn--r8jz45g.jp" in payload
    assert payload.isascii()
    mail_args = command_arguments(protocol.commands, b"MAIL")
    assert b"SMTPUTF8" not in mail_args
