"""
Structured send results: envelope rejection, incomplete body, confirmed
delivery, and uncertain delivery status.
"""

import asyncio
from typing import cast

import pytest

from aiosmtplib import (
    SMTP,
    SendResult,
    SendStage,
    SendStatus,
    SMTPSendError,
    SMTPServerDisconnected,
)

from .smtpd import (
    mock_response_data_disconnect_after_terminator,
    mock_response_data_disconnect_before_data,
    mock_response_data_ok_then_disconnect,
    mock_response_data_stall_after_terminator,
    mock_response_disconnect,
    mock_response_mailbox_unavailable,
    mock_response_rcpt_refuse_specific,
    mock_response_start_data_disconnect,
    mock_response_start_data_stall,
)


def result_of(excinfo: pytest.ExceptionInfo[BaseException]) -> SendResult:
    result = getattr(excinfo.value, "send_result", None)
    assert isinstance(result, SendResult)
    return result


async def test_delivered_result(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        result = await smtp_client.sendmail_result(
            sender_str, [recipient_str], message_str
        )

    assert isinstance(result, SendResult)
    assert result.status is SendStatus.delivered
    assert result.is_delivered
    assert not result.is_uncertain
    assert result.stage is None
    assert result.error is None
    assert result.response
    assert result.accepted_recipients == (recipient_str,)
    assert dict(result.refused_recipients) == {}


@pytest.mark.smtpd_mocks(smtp_RCPT=mock_response_rcpt_refuse_specific)
async def test_delivered_result_with_partial_refusal(
    smtp_client: SMTP, sender_str: str, message_str: str
) -> None:
    accepted = "accepted@example.com"
    refused = "refused@example.com"

    async with smtp_client:
        result = await smtp_client.sendmail_result(
            sender_str, [accepted, refused], message_str
        )

    assert result.status is SendStatus.delivered
    assert result.accepted_recipients == (accepted,)
    assert list(result.refused_recipients) == [refused]
    assert result.refused_recipients[refused].code == 550


@pytest.mark.smtpd_mocks(smtp_MAIL=mock_response_mailbox_unavailable)
async def test_envelope_rejected_at_mail(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
    received_commands: list[tuple[str, tuple[object, ...]]],
) -> None:
    async with smtp_client:
        with pytest.raises(Exception) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = result_of(excinfo)
    assert result.status is SendStatus.rejected
    assert result.stage is SendStage.mail
    assert result.accepted_recipients == ()
    assert result.can_retry
    assert result.error is excinfo.value
    # A definitive refusal is reset, not dropped or retried.
    assert received_commands[-1][0] == "RSET"


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_start_data_disconnect)
async def test_incomplete_body_disconnect_at_data_prompt(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    # The server sends 354 then immediately closes; none of the body is
    # submitted, so the message can safely be retried.
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.incomplete
    assert result.stage in (SendStage.data, SendStage.data_body)
    assert result.accepted_recipients == (recipient_str,)
    assert result.can_retry
    assert not result.is_uncertain
    assert isinstance(excinfo.value.__cause__, SMTPServerDisconnected)
    assert not smtp_client.is_connected


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_disconnect_before_data)
async def test_rejected_disconnect_before_data_prompt(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    # The connection drops in place of the 354 response: the server never
    # agreed to accept the body.
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.rejected
    assert result.stage is SendStage.data
    assert result.accepted_recipients == (recipient_str,)
    assert isinstance(result.error, SMTPServerDisconnected)
    assert isinstance(excinfo.value.__cause__, SMTPServerDisconnected)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_disconnect_after_terminator)
async def test_uncertain_disconnect_after_terminator(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.uncertain
    assert result.is_uncertain
    assert not result.can_retry
    assert result.stage is SendStage.data_response
    assert result.accepted_recipients == (recipient_str,)
    assert isinstance(excinfo.value.__cause__, SMTPServerDisconnected)
    # The uncertain connection is dropped, never silently reused or retried.
    assert not smtp_client.is_connected


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_ok_then_disconnect)
async def test_delivered_disconnect_after_250(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    # The 250 was received before the close: delivery is confirmed regardless
    # of the dropped connection.
    async with smtp_client:
        result = await smtp_client.sendmail_result(
            sender_str, [recipient_str], message_str
        )

    assert result.status is SendStatus.delivered
    assert result.is_delivered
    assert result.response == "OK"
    assert result.accepted_recipients == (recipient_str,)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_stall_after_terminator)
async def test_uncertain_read_timeout_after_terminator(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.uncertain
    assert result.stage is SendStage.data_response
    assert isinstance(excinfo.value.__cause__, TimeoutError)
    assert not smtp_client.is_connected


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_start_data_stall)
async def test_incomplete_timeout_while_sending_body(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
) -> None:
    big_message = "Subject: big\r\n\r\n" + ("x" * 2_000_000)

    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], big_message)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.incomplete
    assert result.stage is SendStage.data_body
    assert result.can_retry


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_data_disconnect_after_terminator)
async def test_cancel_after_terminator_is_uncertain(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        send_task = asyncio.ensure_future(
            smtp_client.sendmail_result(sender_str, [recipient_str], message_str)
        )
        # Let the full transaction reach the wait for the final 250.
        await asyncio.sleep(0.3)
        send_task.cancel()

        with pytest.raises(asyncio.CancelledError) as excinfo:
            await send_task

    result = cast(SendResult | None, getattr(excinfo.value, "send_result", None))
    assert result is not None
    assert result.status is SendStatus.uncertain
    assert result.stage is SendStage.data_response
    assert result.accepted_recipients == (recipient_str,)


@pytest.mark.smtpd_mocks(smtp_DATA=mock_response_start_data_stall)
async def test_cancel_while_sending_body_is_incomplete(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
) -> None:
    big_message = "Subject: big\r\n\r\n" + ("x" * 2_000_000)

    async with smtp_client:
        send_task = asyncio.ensure_future(
            smtp_client.sendmail_result(sender_str, [recipient_str], big_message)
        )
        await asyncio.sleep(0.1)
        send_task.cancel()

        with pytest.raises(asyncio.CancelledError) as excinfo:
            await send_task

    result = cast(SendResult | None, getattr(excinfo.value, "send_result", None))
    assert result is not None
    assert result.status is SendStatus.incomplete
    assert result.stage is SendStage.data_body
    assert result.can_retry


@pytest.mark.smtpd_mocks(smtp_MAIL=mock_response_disconnect)
async def test_disconnect_during_mail_records_stage(
    smtp_client: SMTP,
    sender_str: str,
    recipient_str: str,
    message_str: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPSendError) as excinfo:
            await smtp_client.sendmail_result(sender_str, [recipient_str], message_str)

    result = excinfo.value.send_result
    assert result is not None
    assert result.status is SendStatus.incomplete
    assert result.stage is SendStage.mail
    assert result.accepted_recipients == ()
    assert isinstance(excinfo.value.__cause__, SMTPServerDisconnected)


async def test_legacy_sendmail_return_is_preserved(
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
    assert response
