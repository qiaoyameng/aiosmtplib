# pyright: strict

import email.message
import pathlib
import socket
import ssl

import aiosmtplib
from aiosmtplib.email import MessageSendPlan, plan_message


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


async def plan_and_prepare_message() -> None:
    message = email.message.EmailMessage()
    plan: MessageSendPlan = plan_message(message)
    requiring_utf8: frozenset[str] = plan.addresses_requiring_utf8
    async with aiosmtplib.SMTP(hostname="smtp.example.com") as smtp:
        planned, mail_options, flat_message = await smtp.prepare_message(message)
        sender, recipients = planned.envelope(smtputf8=True)
        await smtp.sendmail(sender, recipients, flat_message, mail_options=mail_options)
