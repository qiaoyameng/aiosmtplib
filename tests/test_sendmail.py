"""
SMTP.sendmail and SMTP.send_message method testing.
"""

import asyncio
import copy
import email.generator
import email.header
import email.message
from typing import Any

import pytest

from aiosmtplib import (
    SMTP,
    SMTPSendError,
    SMTPNotSupported,
    SMTPRecipientsRefused,
    SMTPResponseException,
    SMTPServerDisconnected,
    SMTPReadTimeoutError,
    SMTPStatus,
    SendStage,
)

from .smtpd import (
    RecordingHandler,
    mock_response_data_disconnect_after_terminator,
    mock_response_data_ok_then_disconnect,
    mock_response_data_stall_after_terminator,
    mock_response_delayed_ok,
    mock_response_disconnect,
    mock_response_done,
    mock_response_error_disconnect,
    mock_response_bad_command_sequence,
    mock_response_mailbox_unavailable,
)


async def test_sendmail_simple_success(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, [recipient_str], message_str
        )

        assert not errors
        assert isinstance(errors, dict)
        assert response != ""


async def test_sendmail_binary_content(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, [recipient_str], bytes(message_str, "ascii")
        )

        assert not errors
        assert isinstance(errors, dict)
        assert response != ""


async def test_sendmail_with_recipients_string(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, recipient_str, message_str
        )

        assert not errors
        assert response != ""


async def test_sendmail_with_mail_option(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, [recipient_str], message_str, mail_options=["BODY=8BITMIME"]
        )

        assert not errors
        assert response != ""


@pytest.mark.smtpd_mocks(smtp_EHLO=mock_response_done)
async def test_sendmail_without_size_option(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, [recipient_str], message_str
        )

        assert not errors
        assert response != ""


async def test_sendmail_with_invalid_mail_option(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPResponseException) as excinfo:
            await smtp_client.sendmail(
                sender_str,
                [recipient_str],
                message_str,
                mail_options=["BADDATA=0x00000000"],
            )

        assert excinfo.value.code == SMTPStatus.syntax_error


async def test_sendmail_with_rcpt_option(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPRecipientsRefused) as excinfo:
            await smtp_client.sendmail(
                sender_str,
                [recipient_str],
                message_str,
                rcpt_options=["NOTIFY=FAILURE,DELAY"],
            )

        recipient_exc = excinfo.value.recipients[0]
        assert recipient_exc.code == SMTPStatus.syntax_error
        assert (
            recipient_exc.message
            == "RCPT TO parameters not recognized or not implemented"
        )


async def test_sendmail_simple_failure(smtp_client: SMTP) -> None:
    async with smtp_client:
        with pytest.raises(SMTPRecipientsRefused):
            #  @@ is an invalid recipient.
            await smtp_client.sendmail("test@example.com", ["@@"], "blah")


async def test_sendmail_smtputf8_not_supported(smtp_client: SMTP) -> None:
    async with smtp_client:
        with pytest.raises(SMTPNotSupported, match="SMTPUTF8 is not supported"):
            await smtp_client.sendmail(
                "test@example.com",
                ["børk@example.com"],
                "blah",
                mail_options=["SMTPUTF8"],
            )


async def test_sendmail_non_ascii_recipient_without_smtputf8(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    async with smtp_client:
        with pytest.raises(UnicodeEncodeError):
            await smtp_client.sendmail("test@example.com", ["børk@example.com"], "blah")

        # No envelope was started, so a subsequent send still works
        assert not any(command == "MAIL" for command, _ in received_commands)
        await smtp_client.sendmail("test@example.com", ["ok@example.com"], "blah")


async def test_sendmail_no_recipients(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    async with smtp_client:
        with pytest.raises(ValueError, match="No recipients"):
            await smtp_client.sendmail("test@example.com", [], "blah")

        assert not any(command == "MAIL" for command, _ in received_commands)
        await smtp_client.sendmail("test@example.com", ["ok@example.com"], "blah")


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_error_disconnect)
async def test_sendmail_error_silent_rset_handles_disconnect(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPResponseException):
            await smtp_client.sendmail(sender_str, [recipient_str], message_str)


@pytest.mark.smtpd_mocks(smtp_MAIL=mock_response_mailbox_unavailable)
async def test_rset_after_sendmail_error_response_to_mail(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    """
    If an error response is given to the MAIL command in the sendmail method,
    test that we reset the server session.
    """
    async with smtp_client:
        response = await smtp_client.ehlo()
        assert response.code == SMTPStatus.completed

        with pytest.raises(SMTPResponseException) as excinfo:
            await smtp_client.sendmail(
                "test@example.com", ["test@example.com"], "Hello World"
            )

        assert excinfo.value.code == SMTPStatus.mailbox_unavailable
        assert received_commands[-1][0] == "RSET"


@pytest.mark.smtpd_mocks(smtp_RCPT=mock_response_mailbox_unavailable)
async def test_rset_after_sendmail_error_response_to_rcpt(
    smtp_client: SMTP,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    """
    If an error response is given to the RCPT command in the sendmail method,
    test that we reset the server session.
    """
    async with smtp_client:
        response = await smtp_client.ehlo()
        assert response.code == SMTPStatus.completed

        with pytest.raises(SMTPRecipientsRefused) as excinfo:
            await smtp_client.sendmail(
                "test@example.com", ["test@example.com"], "Hello World"
            )

        assert excinfo.value.recipients[0].code == SMTPStatus.mailbox_unavailable
        assert received_commands[-1][0] == "RSET"


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_bad_command_sequence)
async def test_rset_after_sendmail_error_response_to_data(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    """
    If an error response is given to the DATA command in the sendmail method,
    test that we reset the server session.
    """
    async with smtp_client:
        response = await smtp_client.ehlo()
        assert response.code == SMTPStatus.completed

        with pytest.raises(SMTPResponseException) as excinfo:
            await smtp_client.sendmail(sender_str, [recipient_str], message_str)

        assert excinfo.value.code == SMTPStatus.bad_command_sequence
        assert received_commands[-1][0] == "RSET"


async def test_send_message(smtp_client: SMTP, message: email.message.Message) -> None:
    async with smtp_client:
        errors, response = await smtp_client.send_message(message)

    assert not errors
    assert isinstance(errors, dict)
    assert response != ""


async def test_send_message_with_sender_and_recipient_args(
    smtp_client: SMTP,
    message: email.message.EmailMessage,
    received_messages: list[email.message.EmailMessage],
) -> None:
    sender = "sender2@example.com"
    recipients = ["recipient1@example.com", "recipient2@example.com"]
    async with smtp_client:
        errors, response = await smtp_client.send_message(
            message, sender=sender, recipients=recipients
        )

    assert not errors
    assert isinstance(errors, dict)
    assert response != ""

    assert len(received_messages) == 1
    assert received_messages[0]["X-MailFrom"] == sender
    assert received_messages[0]["X-RcptTo"] == ", ".join(recipients)


async def test_send_message_with_cc_recipients(
    smtp_client: SMTP,
    recipient_str: str,
    message: email.message.EmailMessage,
    received_messages: list[email.message.EmailMessage],
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    cc_recipients = ["recipient1@example.com", "recipient2@example.com"]
    message["Cc"] = ", ".join(cc_recipients)

    async with smtp_client:
        errors, _ = await smtp_client.send_message(message)

    assert not errors

    assert len(received_messages) == 1
    assert (
        received_messages[0]["X-RcptTo"]
        == f"{recipient_str}, {', '.join(cc_recipients)}"
    )

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == recipient_str
    assert received_commands[3][0] == "RCPT"
    assert received_commands[3][1][0] == cc_recipients[0]
    assert received_commands[4][0] == "RCPT"
    assert received_commands[4][1][0] == cc_recipients[1]


async def test_send_message_with_bcc_recipients(
    smtp_client: SMTP,
    recipient_str: str,
    message: email.message.EmailMessage,
    received_messages: list[email.message.EmailMessage],
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    bcc_recipients = ["recipient1@example.com", "recipient2@example.com"]
    message["Bcc"] = ", ".join(bcc_recipients)

    async with smtp_client:
        errors, _ = await smtp_client.send_message(message)

    assert not errors

    assert len(received_messages) == 1

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == recipient_str
    assert received_commands[3][0] == "RCPT"
    assert received_commands[3][1][0] == bcc_recipients[0]
    assert received_commands[4][0] == "RCPT"
    assert received_commands[4][1][0] == bcc_recipients[1]


async def test_send_message_with_cc_and_bcc_recipients(
    smtp_client: SMTP,
    recipient_str: str,
    message: email.message.EmailMessage,
    received_messages: list[email.message.EmailMessage],
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    cc_recipient = "recipient2@example.com"
    message["Cc"] = cc_recipient
    bcc_recipient = "recipient3@example.com"
    message["Bcc"] = bcc_recipient

    async with smtp_client:
        errors, _ = await smtp_client.send_message(message)

    assert not errors

    assert len(received_messages) == 1
    assert received_messages[0]["To"] == recipient_str
    assert received_messages[0]["Cc"] == cc_recipient
    # BCC shouldn't be passed through
    assert received_messages[0]["Bcc"] is None

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == recipient_str
    assert received_commands[3][0] == "RCPT"
    assert received_commands[3][1][0] == cc_recipient
    assert received_commands[4][0] == "RCPT"
    assert received_commands[4][1][0] == bcc_recipient


async def test_send_message_recipient_str(
    smtp_client: SMTP,
    message: email.message.EmailMessage,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    recipient_str = "1234@example.org"
    async with smtp_client:
        errors, response = await smtp_client.send_message(
            message, recipients=recipient_str
        )

    assert not errors
    assert isinstance(errors, dict)
    assert response != ""
    assert received_commands[2][1][0] == recipient_str


async def test_send_message_mail_options(
    smtp_client: SMTP,
    message: email.message.EmailMessage,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.send_message(
            message, mail_options=["BODY=8BITMIME"]
        )

    assert not errors
    assert isinstance(errors, dict)
    assert response != ""


async def test_send_multiple_messages_in_sequence(
    smtp_client: SMTP, message: email.message.EmailMessage
) -> None:
    message1 = copy.copy(message)

    message2 = copy.copy(message)
    del message2["To"]
    message2["To"] = "recipient2@example.com"

    async with smtp_client:
        errors1, response1 = await smtp_client.send_message(message1)

        assert not errors1
        assert isinstance(errors1, dict)
        assert response1 != ""

        errors2, response2 = await smtp_client.send_message(message2)

        assert not errors2
        assert isinstance(errors2, dict)
        assert response2 != ""


async def test_send_message_without_recipients(
    smtp_client: SMTP, message: email.message.EmailMessage
) -> None:
    del message["To"]

    async with smtp_client:
        with pytest.raises(ValueError):
            await smtp_client.send_message(message)


async def test_send_message_without_sender(
    smtp_client: SMTP, message: email.message.EmailMessage
) -> None:
    del message["From"]

    async with smtp_client:
        with pytest.raises(ValueError):
            await smtp_client.send_message(message)


@pytest.mark.parametrize(
    "message", ["email_message", "compat32_message", "mime_message"], indirect=True
)
@pytest.mark.smtpd_options(smtputf8=True)
async def test_send_message_smtputf8_sender(
    smtp_client: SMTP,
    message: email.message.EmailMessage | email.message.Message,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
) -> None:
    del message["From"]
    message["From"] = "séndër@exåmple.com"

    async with smtp_client:
        errors, response = await smtp_client.send_message(message)

    assert not errors
    assert response != ""

    assert received_commands[1][0] == "MAIL"
    assert received_commands[1][1][0] == message["From"]
    # Size varies depending on the message type
    assert received_commands[1][1][1][0].startswith("SIZE=")
    assert received_commands[1][1][1][1:] == ["SMTPUTF8", "BODY=8BITMIME"]

    assert len(received_messages) == 1
    assert received_messages[0]["X-MailFrom"] == message["From"]


@pytest.mark.smtpd_options(smtputf8=True)
@pytest.mark.parametrize(
    "mail_options",
    (None, ["SMTPUTF8"]),
    ids=("no_mail_options", "smtputf8_option"),
)
async def test_send_mime_message_smtputf8_recipient(
    smtp_client: SMTP,
    mime_message: email.message.EmailMessage,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
    mail_options: list[str] | None,
) -> None:
    mime_message["To"] = "reçipïént@exåmple.com"

    async with smtp_client:
        errors, response = await smtp_client.send_message(
            mime_message, mail_options=mail_options
        )

    assert not errors
    assert response != ""

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == mime_message["To"]

    assert len(received_messages) == 1
    assert received_messages[0]["X-RcptTo"] == ", ".join(mime_message.get_all("To"))


@pytest.mark.smtpd_options(smtputf8=True)
async def test_send_compat32_message_smtputf8_recipient(
    smtp_client: SMTP,
    compat32_message: email.message.Message,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
) -> None:
    recipient_bytes = bytes("reçipïént@exåmple.com", "utf-8")
    compat32_message["To"] = email.header.Header(recipient_bytes, "utf-8")

    async with smtp_client:
        errors, response = await smtp_client.send_message(compat32_message)

    assert not errors
    assert response != ""

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == compat32_message["To"]

    assert len(received_messages) == 1
    assert (
        received_messages[0]["X-RcptTo"]
        == "recipient@example.com, reçipïént@exåmple.com"
    )


@pytest.mark.smtpd_options(smtputf8=False)
async def test_send_message_smtputf8_not_supported(
    smtp_client: SMTP, message: email.message.EmailMessage
) -> None:
    del message["To"]
    message["To"] = "reçipïént2@exåmple.com"

    async with smtp_client:
        with pytest.raises(SMTPNotSupported):
            await smtp_client.send_message(message)


@pytest.mark.smtpd_options(smtputf8=False)
async def test_send_compat32_message_utf8_text_without_smtputf8(
    smtp_client: SMTP,
    compat32_message: email.message.Message,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
) -> None:
    compat32_message["To"] = email.header.Header(
        "reçipïént <recipient2@example.com>", "utf-8"
    )

    async with smtp_client:
        errors, response = await smtp_client.send_message(compat32_message)

    assert not errors
    assert response != ""

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == compat32_message["To"].encode()

    assert len(received_messages) == 1
    assert (
        received_messages[0]["X-RcptTo"]
        == "recipient@example.com, recipient2@example.com"
    )
    # Name should be encoded
    assert received_messages[0].get_all("To") == [
        "recipient@example.com",
        "=?utf-8?b?cmXDp2lww6/DqW50IDxyZWNpcGllbnQyQGV4YW1wbGUuY29tPg==?=",
    ]


@pytest.mark.smtpd_options(smtputf8=False)
async def test_send_mime_message_utf8_text_without_smtputf8(
    smtp_client: SMTP,
    mime_message: email.message.EmailMessage,
    received_commands: list[tuple[str, tuple[Any, ...]]],
    received_messages: list[email.message.EmailMessage],
) -> None:
    mime_message["To"] = "reçipïént <recipient2@example.com>"

    async with smtp_client:
        errors, response = await smtp_client.send_message(mime_message)

    assert not errors
    assert response != ""

    assert received_commands[2][0] == "RCPT"
    assert received_commands[2][1][0] == mime_message["To"]

    assert len(received_messages) == 1
    assert (
        received_messages[0]["X-RcptTo"]
        == "recipient@example.com, recipient2@example.com"
    )
    # Name should be encoded
    assert received_messages[0].get_all("To") == [
        "recipient@example.com",
        "=?utf-8?b?cmXDp2lww6/DqW50IDxyZWNpcGllbnQyQGV4YW1wbGUuY29tPg==?=",
    ]


@pytest.mark.parametrize(
    "message", ["email_message", "compat32_message", "mime_message"], indirect=True
)
@pytest.mark.smtpd_options(**{"smtputf8": False, "7bit": True})
async def test_send_message_7bit(
    smtp_client: SMTP,
    message: email.message.EmailMessage | email.message.Message,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.send_message(message)

    assert not errors
    assert response != ""

    assert "BODY=8BITMIME" not in received_commands[1][1][1]


async def test_sendmail_empty_sender(
    smtp_client: SMTP, recipient_str: str, message_str: str
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail("", [recipient_str], message_str)

        assert not errors
        assert isinstance(errors, dict)
        assert response != ""


async def test_sendmail_size_option_counts_transmitted_octets_bytes(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    # Bare LF line endings are converted to CRLF on the wire, the body has
    # multibyte UTF-8, and there is no trailing newline (one gets added).
    message = b"From: a@example.com\nTo: b@example.com\n\nH\xc3\xa9llo\n.dot"
    expected_size = len(
        b"From: a@example.com\r\nTo: b@example.com\r\n\r\nH\xc3\xa9llo\r\n.dot\r\n"
    )

    async with smtp_client:
        await smtp_client.sendmail(sender_str, [recipient_str], message)

    assert received_commands[1][0] == "MAIL"
    assert received_commands[1][1][1][0] == f"SIZE={expected_size}"


async def test_sendmail_size_option_counts_transmitted_octets_str(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    message = "From: a@example.com\nTo: b@example.com\n\nHello\n"
    expected_size = len(b"From: a@example.com\r\nTo: b@example.com\r\n\r\nHello\r\n")

    async with smtp_client:
        await smtp_client.sendmail(sender_str, [recipient_str], message)

    assert received_commands[1][0] == "MAIL"
    assert received_commands[1][1][1][0] == f"SIZE={expected_size}"


async def test_sendmail_size_option_not_duplicated(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
    received_commands: list[tuple[str, tuple[Any, ...]]],
) -> None:
    async with smtp_client:
        await smtp_client.sendmail(
            sender_str, [recipient_str], message_str, mail_options=["SIZE=42"]
        )

    assert received_commands[1][0] == "MAIL"
    assert received_commands[1][1][1] == ["SIZE=42"]


@pytest.mark.smtpd_mocks(smtp_RCPT=mock_response_disconnect)
async def test_sendmail_disconnect_before_data_records_envelope_stage(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail(sender_str, [recipient_str], message_str)

    error = excinfo.value
    assert error.stage is SendStage.ENVELOPE
    assert not error.delivery_uncertain
    assert error.accepted_recipients == ()
    assert error.refused_recipients == {}
    assert isinstance(error.__cause__, SMTPServerDisconnected)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_disconnect)
async def test_sendmail_disconnect_on_data_records_content_stage(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail(sender_str, [recipient_str], message_str)

    error = excinfo.value
    assert error.stage is SendStage.CONTENT
    assert not error.delivery_uncertain
    assert error.accepted_recipients == (recipient_str,)
    assert isinstance(error.__cause__, SMTPServerDisconnected)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_disconnect_after_terminator)
async def test_sendmail_disconnect_after_terminator_delivery_uncertain(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail(sender_str, [recipient_str], message_str)

    error = excinfo.value
    assert error.stage is SendStage.CONFIRMATION
    assert error.delivery_uncertain
    assert error.accepted_recipients == (recipient_str,)
    assert isinstance(error.__cause__, SMTPServerDisconnected)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_disconnect_after_terminator)
async def test_sendmail_disconnect_after_terminator_records_recipients(
    smtp_client: SMTP,
    smtpd_handler: RecordingHandler,
    monkeypatch: pytest.MonkeyPatch,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async def refuse_one_recipient(
        server: Any,
        session: Any,
        envelope: Any,
        address: str,
        rcpt_options: Any,
    ) -> str:
        if address == "refused@example.com":
            return "550 no such user"
        return "250 OK"

    monkeypatch.setattr(smtpd_handler, "handle_RCPT", refuse_one_recipient)

    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail(
                sender_str, [recipient_str, "refused@example.com"], message_str
            )

    error = excinfo.value
    assert error.delivery_uncertain
    assert error.accepted_recipients == (recipient_str,)
    refused = error.refused_recipients["refused@example.com"]
    assert refused.code == SMTPStatus.mailbox_does_not_exist


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_stall_after_terminator)
async def test_sendmail_timeout_after_terminator_delivery_uncertain(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail(
                sender_str, [recipient_str], message_str, timeout=0.1
            )

    error = excinfo.value
    assert error.stage is SendStage.CONFIRMATION
    assert error.delivery_uncertain
    assert error.accepted_recipients == (recipient_str,)
    assert isinstance(error.__cause__, SMTPReadTimeoutError)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_ok_then_disconnect)
async def test_sendmail_disconnect_after_ok_is_confirmed(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        errors, response = await smtp_client.sendmail(
            sender_str, [recipient_str], message_str
        )

    assert errors == {}
    assert response == "OK, message accepted for delivery"


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_stall_after_terminator)
async def test_sendmail_cancelled_after_terminator_preserves_stage(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    await smtp_client.connect()
    send_task = asyncio.create_task(
        smtp_client.sendmail(sender_str, [recipient_str], message_str)
    )
    await asyncio.sleep(0.2)
    send_task.cancel()

    with pytest.raises(asyncio.CancelledError) as excinfo:
        await send_task

    send_error = excinfo.value.send_error
    assert send_error.stage is SendStage.CONFIRMATION
    assert send_error.delivery_uncertain
    assert send_error.accepted_recipients == (recipient_str,)
    assert not smtp_client.is_connected


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_delayed_ok)
async def test_sendmail_cancelled_before_data_response_preserves_stage(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    await smtp_client.connect()
    send_task = asyncio.create_task(
        smtp_client.sendmail(sender_str, [recipient_str], message_str)
    )
    await asyncio.sleep(0.2)
    send_task.cancel()

    with pytest.raises(asyncio.CancelledError) as excinfo:
        await send_task

    send_error = excinfo.value.send_error
    assert send_error.stage is SendStage.CONTENT
    assert not send_error.delivery_uncertain
    assert send_error.accepted_recipients == (recipient_str,)
    assert not smtp_client.is_connected
