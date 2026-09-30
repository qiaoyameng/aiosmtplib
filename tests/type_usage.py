# pyright: strict

import email.message
import pathlib
import socket
import ssl

import aiosmtplib


async def send_str() -> None:
    await aiosmtplib.send("test")


async def send_message() -> None:
    message = email.message.EmailMessage()
    await aiosmtplib.send(message)


async def send_all_options() -> None:
    await aiosmtplib.send(
        "test",
        sender="test@example.com",
        recipients=["user1@example.com"],
        mail_options=["FOO"],
        rcpt_options=["BAR"],
        hostname="smtp.example.com",
        port=1234,
        username="root@example.com",
        password="changeme",
        local_hostname="test",
        source_address=("foo", 123),
        timeout=124.34,
        use_tls=True,
        start_tls=False,
        validate_certs=False,
        client_cert="test",
        client_key="test",
        tls_context=ssl.create_default_context(),
        cert_bundle="test",
        socket_path=pathlib.PurePath("/tmp/foo"),
        sock=socket.socket(),
    )


async def send_message_async_context_manager() -> None:
    message = email.message.EmailMessage()
    async with aiosmtplib.SMTP(hostname="smtp.example.com") as smtp:
        await smtp.send_message(message)


async def sendmail_result_usage() -> None:
    result: aiosmtplib.SendResult | None
    async with aiosmtplib.SMTP(hostname="smtp.example.com") as smtp:
        try:
            result = await smtp.sendmail_result(
                "sender@example.com", ["recipient@example.com"], "Hello"
            )
        except aiosmtplib.SMTPSendError as exc:
            result = exc.send_result

    assert result is not None
    if result.status is aiosmtplib.SendStatus.uncertain:
        # Do not resend automatically; surface for a human decision.
        stage: aiosmtplib.SendStage | None = result.stage
        accepted: tuple[str, ...] = result.accepted_recipients
        del stage, accepted


async def send_message_result_usage() -> None:
    message = email.message.EmailMessage()
    async with aiosmtplib.SMTP(hostname="smtp.example.com") as smtp:
        result: aiosmtplib.SendResult = await smtp.send_message_result(message)
    assert result.is_delivered
