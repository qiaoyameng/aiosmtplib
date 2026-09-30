"""
SMTP.plan_message and send capability planning tests.
"""

import email.header
import email.message
from typing import Any

import pytest

from aiosmtplib import SMTP, SendPlan, SMTPNotSupported
from aiosmtplib.plan import build_send_plan


def make_message(
    from_header: str = "sender@example.com",
    to_header: str = "recipient@example.com",
    subject: str = "A message",
    body: str = "Hello World",
) -> email.message.EmailMessage:
    message = email.message.EmailMessage()
    message["From"] = from_header
    message["To"] = to_header
    message["Subject"] = subject
    message.set_content(body)

    return message


async def test_plan_message_ascii(
    smtp_client: SMTP, email_message: email.message.EmailMessage
) -> None:
    async with smtp_client:
        plan = await smtp_client.plan_message(email_message)

    assert isinstance(plan, SendPlan)
    assert plan.smtputf8 is False
    assert plan.eightbitmime is True
    assert plan.downgrades == ()
    assert plan.sender == "sender@example.com"
    assert plan.recipients == ("recipient@example.com",)
    assert plan.mail_options == ("BODY=8BITMIME",)
    assert plan.message.isascii()


@pytest.mark.smtpd_options(smtputf8=False)
async def test_plan_message_chinese_display_name(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
) -> None:
    # A non-ASCII display name does not require SMTPUTF8: the envelope is
    # ASCII, and the header is RFC 2047 encoded when serialized.
    message = make_message(
        from_header="张三 <sender@example.com>",
        to_header="李四 <recipient@example.com>",
        subject="测试",
    )

    async with smtp_client:
        plan = await smtp_client.plan_message(message)
        errors, _ = await smtp_client.send_message(message)

    assert not errors
    assert plan.smtputf8 is False
    assert plan.downgrades == ("Non-ASCII header content will be RFC 2047 encoded",)
    assert plan.message.isascii()

    mail_command = received_commands[1]
    assert mail_command[0] == "MAIL"
    assert "SMTPUTF8" not in mail_command[1][1]

    assert received_messages[0]["From"] == "=?utf-8?b?5byg5LiJ?= <sender@example.com>"
    assert received_messages[0]["To"] == "=?utf-8?b?5p2O5Zub?= <recipient@example.com>"


@pytest.mark.smtpd_options(smtputf8=False)
async def test_plan_message_internationalized_domain(
    smtp_client: SMTP,
    email_message: email.message.EmailMessage,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    # Non-ASCII envelope domains are IDNA encoded, so SMTPUTF8 is not needed.
    async with smtp_client:
        plan = await smtp_client.plan_message(
            email_message,
            sender="user@例え.jp",
            recipients=["rcpt@例え.jp"],
        )
        errors, _ = await smtp_client.send_message(
            email_message,
            sender="user@例え.jp",
            recipients=["rcpt@例え.jp"],
        )

    assert not errors
    assert plan.smtputf8 is False
    assert plan.sender == "user@xn--r8jz45g.jp"
    assert plan.recipients == ("rcpt@xn--r8jz45g.jp",)
    assert plan.downgrades == (
        "IDNA encoded domain '例え.jp' as 'xn--r8jz45g.jp'",
        "IDNA encoded domain '例え.jp' as 'xn--r8jz45g.jp'",
    )

    mail_command = received_commands[1]
    assert mail_command[0] == "MAIL"
    assert mail_command[1][0] == plan.sender
    assert "SMTPUTF8" not in mail_command[1][1]

    rcpt_command = received_commands[2]
    assert rcpt_command[0] == "RCPT"
    assert rcpt_command[1][0] == plan.recipients[0]


@pytest.mark.smtpd_options(smtputf8=True)
async def test_plan_message_non_ascii_local_part(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    # A non-ASCII local part cannot be downgraded; it is sent as-is with
    # SMTPUTF8, never transliterated.
    message = make_message(to_header="用户@example.com")

    async with smtp_client:
        plan = await smtp_client.plan_message(message)
        errors, _ = await smtp_client.send_message(message)

    assert not errors
    assert plan.smtputf8 is True
    assert plan.recipients == ("用户@example.com",)
    assert plan.downgrades == ()
    assert "SMTPUTF8" in plan.mail_options

    rcpt_command = received_commands[2]
    assert rcpt_command[0] == "RCPT"
    assert rcpt_command[1][0] == "用户@example.com"


@pytest.mark.smtpd_options(smtputf8=False)
async def test_plan_message_non_ascii_local_part_not_supported(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    message = make_message(to_header="用户@example.com")

    async with smtp_client:
        with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
            await smtp_client.plan_message(message)
        with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
            await smtp_client.send_message(message)

    # The failure must happen before MAIL FROM is sent
    assert all(command[0] != "MAIL" for command in received_commands)


async def test_plan_message_matches_send_message(
    smtp_client: SMTP,
    email_message: email.message.EmailMessage,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    async with smtp_client:
        plan = await smtp_client.plan_message(email_message)
        errors, _ = await smtp_client.send_message(email_message)

    assert not errors

    mail_command = next(cmd for cmd in received_commands if cmd[0] == "MAIL")
    assert mail_command[1][0] == plan.sender
    for option in plan.mail_options:
        assert option in mail_command[1][1]

    rcpt_commands = [cmd for cmd in received_commands if cmd[0] == "RCPT"]
    assert [cmd[1][0] for cmd in rcpt_commands] == list(plan.recipients)


async def test_plan_message_recipient_str(
    smtp_client: SMTP, email_message: email.message.EmailMessage
) -> None:
    async with smtp_client:
        plan = await smtp_client.plan_message(
            email_message, recipients="other@example.com"
        )

    assert plan.recipients == ("other@example.com",)


async def test_plan_message_without_sender(
    smtp_client: SMTP, email_message: email.message.EmailMessage
) -> None:
    del email_message["From"]

    async with smtp_client:
        with pytest.raises(ValueError):
            await smtp_client.plan_message(email_message)


async def test_plan_message_without_recipients(
    smtp_client: SMTP, email_message: email.message.EmailMessage
) -> None:
    del email_message["To"]

    async with smtp_client:
        with pytest.raises(ValueError):
            await smtp_client.plan_message(email_message)


@pytest.mark.smtpd_options(**{"smtputf8": False, "7bit": True})
async def test_plan_message_7bit_server(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    message = make_message(body="你好")

    async with smtp_client:
        plan = await smtp_client.plan_message(message)
        errors, _ = await smtp_client.send_message(message)

    assert not errors
    assert plan.smtputf8 is False
    assert plan.eightbitmime is False
    assert plan.downgrades == (
        "8BITMIME is not supported; the message body will use a 7bit "
        "content-transfer-encoding",
    )
    assert plan.message.isascii()

    mail_command = received_commands[1]
    assert "BODY=8BITMIME" not in mail_command[1][1]


def test_build_send_plan_smtputf8_option_not_duplicated() -> None:
    message = make_message(to_header="用户@example.com")

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["用户@example.com"],
        mail_options=["SMTPUTF8"],
        smtputf8_supported=True,
        eightbitmime_supported=True,
    )

    assert plan.mail_options.count("SMTPUTF8") == 1


def test_build_send_plan_8bitmime_option_not_duplicated() -> None:
    message = make_message()

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        mail_options=["BODY=8BITMIME"],
        eightbitmime_supported=True,
    )

    assert plan.mail_options.count("BODY=8BITMIME") == 1


def test_build_send_plan_non_idna_domain_requires_utf8() -> None:
    message = make_message()
    domain = "你" * 100 + ".com"

    with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
        build_send_plan(
            message,
            sender=f"user@{domain}",
            recipients=["recipient@example.com"],
            smtputf8_supported=False,
        )

    plan = build_send_plan(
        message,
        sender=f"user@{domain}",
        recipients=["recipient@example.com"],
        smtputf8_supported=True,
        eightbitmime_supported=True,
    )

    assert plan.smtputf8 is True
    assert plan.sender == f"user@{domain}"


def test_build_send_plan_address_without_domain() -> None:
    message = make_message()

    plan = build_send_plan(
        message,
        sender="postmaster",
        recipients=["postmaster"],
        eightbitmime_supported=True,
    )

    assert plan.smtputf8 is False
    assert plan.sender == "postmaster"
    assert plan.recipients == ("postmaster",)
    assert plan.downgrades == ()


def test_build_send_plan_non_ascii_address_without_domain() -> None:
    message = make_message()

    with pytest.raises(SMTPNotSupported, match="SMTPUTF8"):
        build_send_plan(
            message,
            sender="用户",
            recipients=["recipient@example.com"],
            smtputf8_supported=False,
        )


def test_build_send_plan_non_ascii_header_address_requires_utf8() -> None:
    message = email.message.Message()
    message["From"] = "sender@example.com"
    message["To"] = email.header.Header("用户@example.com", "utf-8")
    message.set_payload("Hello World")

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        smtputf8_supported=True,
        eightbitmime_supported=True,
    )

    assert plan.smtputf8 is True
    assert plan.recipients == ("recipient@example.com",)


def test_build_send_plan_non_ascii_subject_does_not_require_utf8() -> None:
    message = make_message(subject="测试")

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        eightbitmime_supported=True,
    )

    assert plan.smtputf8 is False
    assert plan.downgrades == ("Non-ASCII header content will be RFC 2047 encoded",)


def test_build_send_plan_7bit_ascii_message_has_no_downgrades() -> None:
    message = make_message()

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        eightbitmime_supported=False,
    )

    assert plan.eightbitmime is False
    assert plan.downgrades == ()
    assert plan.message.isascii()


def test_build_send_plan_idna_domain_downgrade() -> None:
    message = make_message()

    plan = build_send_plan(
        message,
        sender="user@例え.jp",
        recipients=["rcpt@例え.jp"],
        eightbitmime_supported=True,
    )

    assert plan.smtputf8 is False
    assert plan.sender == "user@xn--r8jz45g.jp"
    assert plan.recipients == ("rcpt@xn--r8jz45g.jp",)
    assert plan.downgrades == (
        "IDNA encoded domain '例え.jp' as 'xn--r8jz45g.jp'",
        "IDNA encoded domain '例え.jp' as 'xn--r8jz45g.jp'",
    )


def test_build_send_plan_7bit_downgrade_note() -> None:
    message = make_message(body="你好")

    plan = build_send_plan(
        message,
        sender="sender@example.com",
        recipients=["recipient@example.com"],
        eightbitmime_supported=False,
    )

    assert plan.smtputf8 is False
    assert plan.eightbitmime is False
    assert plan.downgrades == (
        "8BITMIME is not supported; the message body will use a 7bit "
        "content-transfer-encoding",
    )
    assert plan.message.isascii()
