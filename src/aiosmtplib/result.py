"""
Structured result of a mail transaction (MAIL/RCPT/DATA).

The outcome distinguishes a message that the server definitely rejected from
one that may or may not have been delivered, so callers can decide whether a
retry is safe instead of guessing from the raised exception alone.
"""

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field

from .response import SMTPResponse


__all__ = ("SendResult", "SendStage", "SendStatus")


class SendStage(enum.Enum):
    """
    The stage of a mail transaction at which a failure occurred.
    """

    ehlo = "EHLO"
    mail = "MAIL"
    rcpt = "RCPT"
    data = "DATA"
    data_body = "DATA body"
    data_response = "DATA final response"


class SendStatus(enum.Enum):
    """
    Delivery status of a mail transaction.
    """

    rejected = "rejected"
    incomplete = "incomplete"
    delivered = "delivered"
    uncertain = "uncertain"


@dataclass(frozen=True, slots=True)
class SendResult:
    """
    The outcome of a single :meth:`~aiosmtplib.SMTP.sendmail` transaction.

    :ivar status: Delivery status; see :class:`SendStatus`.
    :ivar stage: Stage the transaction had reached when it failed (``None``
        once the server confirmed acceptance with a 250 response).
    :ivar sender: Envelope sender (MAIL FROM).
    :ivar accepted_recipients: Recipients the server accepted with a 2xx RCPT
        response, in the order they were sent.
    :ivar refused_recipients: Recipients refused with an error response, mapped
        to that response.
    :ivar response: The server's final DATA response message, when delivery was
        confirmed.
    :ivar error: The exception that ended the transaction, if it failed.
    """

    status: SendStatus
    sender: str
    accepted_recipients: tuple[str, ...] = ()
    refused_recipients: Mapping[str, SMTPResponse] = field(default_factory=dict)
    stage: SendStage | None = None
    response: str | None = None
    error: BaseException | None = None

    @property
    def is_delivered(self) -> bool:
        """
        Whether the server confirmed acceptance with a 250 response.
        """
        return self.status is SendStatus.delivered

    @property
    def is_uncertain(self) -> bool:
        """
        Whether delivery status is unknown.

        The message body (including its terminating dot) was fully submitted,
        but the connection was lost, timed out, or the request was cancelled
        before the server's final response arrived. The message may already
        have been delivered, so it must not be resent blindly.
        """
        return self.status is SendStatus.uncertain

    @property
    def can_retry(self) -> bool:
        """
        Whether resending the message cannot result in a duplicate.

        True only when the server rejected the transaction outright or the
        body was not fully submitted.
        """
        return self.status in (SendStatus.rejected, SendStatus.incomplete)
