"""
Test error class imports, arguments, and inheritance.
"""

import asyncio

import pytest
from hypothesis import given
from hypothesis.strategies import integers, lists, text, tuples

from aiosmtplib import (
    SMTPAuthenticationError,
    SMTPConnectError,
    SMTPConnectTimeoutError,
    SMTPDataError,
    SMTPException,
    SMTPHeloError,
    SMTPNotSupported,
    SMTPReadTimeoutError,
    SMTPRecipientRefused,
    SMTPRecipientsRefused,
    SMTPResponse,
    SMTPResponseException,
    SMTPSendError,
    SMTPSenderRefused,
    SMTPServerDisconnected,
    SMTPTimeoutError,
    SendStage,
)


@given(error_message=text())
def test_raise_smtp_exception(error_message: str) -> None:
    with pytest.raises(SMTPException) as excinfo:
        raise SMTPException(error_message)

    assert excinfo.value.message == error_message


@given(code=integers(), error_message=text())
def test_raise_smtp_response_exception(code: int, error_message: str) -> None:
    with pytest.raises(SMTPResponseException) as excinfo:
        raise SMTPResponseException(code, error_message)

    assert issubclass(excinfo.type, SMTPException)
    assert excinfo.value.code == code
    assert excinfo.value.message == error_message


@pytest.mark.parametrize(
    "error_class", (SMTPServerDisconnected, SMTPConnectError, SMTPConnectTimeoutError)
)
@given(error_message=text())
def test_connection_exceptions(
    error_message: str, error_class: type[SMTPException]
) -> None:
    with pytest.raises(error_class) as excinfo:
        raise error_class(error_message)

    assert issubclass(excinfo.type, SMTPException)
    assert issubclass(excinfo.type, ConnectionError)
    assert excinfo.value.message == error_message


@pytest.mark.parametrize(
    "error_class", (SMTPTimeoutError, SMTPConnectTimeoutError, SMTPReadTimeoutError)
)
@given(error_message=text())
def test_timeout_exceptions(
    error_message: str, error_class: type[SMTPException]
) -> None:
    with pytest.raises(error_class) as excinfo:
        raise error_class(error_message)

    assert issubclass(excinfo.type, SMTPException)
    assert issubclass(excinfo.type, asyncio.TimeoutError)
    assert excinfo.value.message == error_message


@pytest.mark.parametrize(
    "error_class", (SMTPHeloError, SMTPDataError, SMTPAuthenticationError)
)
@given(code=integers(), error_message=text())
def test_simple_response_exceptions(
    code: int,
    error_message: str,
    error_class: type[SMTPHeloError | SMTPDataError | SMTPAuthenticationError],
) -> None:
    with pytest.raises(error_class) as excinfo:
        raise error_class(code, error_message)

    assert issubclass(excinfo.type, SMTPResponseException)
    assert excinfo.value.code == code
    assert excinfo.value.message == error_message


@given(code=integers(), error_message=text(), sender=text())
def test_raise_smtp_sender_refused(code: int, error_message: str, sender: str) -> None:
    with pytest.raises(SMTPSenderRefused) as excinfo:
        raise SMTPSenderRefused(code, error_message, sender)

    assert issubclass(excinfo.type, SMTPResponseException)
    assert excinfo.value.code == code
    assert excinfo.value.message == error_message
    assert excinfo.value.sender == sender


@given(code=integers(), error_message=text(), recipient=text())
def test_raise_smtp_recipient_refused(
    code: int, error_message: str, recipient: str
) -> None:
    with pytest.raises(SMTPRecipientRefused) as excinfo:
        raise SMTPRecipientRefused(code, error_message, recipient)

    assert issubclass(excinfo.type, SMTPResponseException)
    assert excinfo.value.code == code
    assert excinfo.value.message == error_message
    assert excinfo.value.recipient == recipient


@given(lists(elements=tuples(integers(), text(), text())))
def test_raise_smtp_recipients_refused(addresses: list[tuple[int, str, str]]) -> None:
    errors = [SMTPRecipientRefused(*address) for address in addresses]
    with pytest.raises(SMTPRecipientsRefused) as excinfo:
        raise SMTPRecipientsRefused(errors)

    assert issubclass(excinfo.type, SMTPException)
    assert excinfo.value.recipients == errors


@pytest.mark.parametrize("recipient_count", (1, 2))
def test_smtp_recipients_refused_message(recipient_count: int) -> None:
    errors = [
        SMTPRecipientRefused(550, "Mailbox unavailable", f"user{index}@example.com")
        for index in range(recipient_count)
    ]

    error = SMTPRecipientsRefused(errors)

    assert error.message == str(errors)
    assert error.args == (errors,)
    assert str(error) == str(errors)


@given(error_message=text())
def test_raise_smtp_not_supported(error_message: str) -> None:
    with pytest.raises(SMTPNotSupported) as excinfo:
        raise SMTPNotSupported(error_message)

    assert issubclass(excinfo.type, SMTPException)
    assert excinfo.value.message == error_message


@given(error_message=text())
def test_smtp_send_error_defaults(error_message: str) -> None:
    error = SMTPSendError(error_message, stage=SendStage.ENVELOPE)

    assert issubclass(SMTPSendError, SMTPException)
    assert error.message == error_message
    assert error.stage is SendStage.ENVELOPE
    assert error.accepted_recipients == ()
    assert error.refused_recipients == {}
    assert not error.delivery_uncertain


@pytest.mark.parametrize(
    ("stage", "expected_uncertain"),
    [
        (SendStage.ENVELOPE, False),
        (SendStage.CONTENT, False),
        (SendStage.CONFIRMATION, True),
    ],
)
def test_smtp_send_error_delivery_uncertain(
    stage: SendStage, expected_uncertain: bool
) -> None:
    error = SMTPSendError(
        "Connection lost",
        stage=stage,
        accepted_recipients=["one@example.com"],
        refused_recipients={"two@example.com": SMTPResponse(550, "no such user")},
    )

    assert error.delivery_uncertain is expected_uncertain
    assert error.accepted_recipients == ("one@example.com",)
    assert error.refused_recipients == {
        "two@example.com": SMTPResponse(550, "no such user")
    }
