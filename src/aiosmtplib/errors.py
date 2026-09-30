import enum
from asyncio import TimeoutError
from collections.abc import Iterable, Mapping

from .response import SMTPResponse


__all__ = (
    "SMTPAuthenticationError",
    "SMTPConnectError",
    "SMTPDataError",
    "SMTPException",
    "SMTPHeloError",
    "SMTPNotSupported",
    "SMTPRecipientRefused",
    "SMTPRecipientsRefused",
    "SMTPResponseException",
    "SMTPSendError",
    "SMTPSenderRefused",
    "SMTPServerDisconnected",
    "SMTPTimeoutError",
    "SMTPConnectTimeoutError",
    "SMTPReadTimeoutError",
    "SMTPConnectResponseError",
    "SendStage",
)


@enum.unique
class SendStage(enum.Enum):
    """
    The stage of an SMTP mail transaction at which a send operation ended.

    Failures before :attr:`CONFIRMATION` mean the server definitely did not
    accept the message. Failure at :attr:`CONFIRMATION` means the message
    content was fully transmitted, but the server's final acknowledgement
    was not received, so the delivery status is unknown.
    """

    ENVELOPE = "envelope"
    CONTENT = "content"
    CONFIRMATION = "confirmation"


class SMTPException(Exception):
    """
    Base class for all SMTP exceptions.
    """

    def __init__(self, message: str, /) -> None:
        self.message = message
        self.args = (message,)


class SMTPServerDisconnected(SMTPException, ConnectionError):
    """
    The connection was lost unexpectedly, or a command was run that requires
    a connection.
    """


class SMTPConnectError(SMTPException, ConnectionError):
    """
    An error occurred while connecting to the SMTP server.
    """


class SMTPTimeoutError(SMTPException, TimeoutError):
    """
    A timeout occurred while performing a network operation.
    """


class SMTPConnectTimeoutError(SMTPTimeoutError, SMTPConnectError):
    """
    A timeout occurred while connecting to the SMTP server.
    """


class SMTPReadTimeoutError(SMTPTimeoutError):
    """
    A timeout occurred while waiting for a response from the SMTP server.
    """


class SMTPNotSupported(SMTPException):
    """
    A command or argument sent to the SMTP server is not supported.
    """


class SMTPResponseException(SMTPException):
    """
    Base class for all server responses with error codes.
    """

    def __init__(self, code: int, message: str, /) -> None:
        self.code = code
        self.message = message
        self.args = (code, message)


class SMTPConnectResponseError(SMTPResponseException, SMTPConnectError):
    """
    The SMTP server returned an invalid response code after connecting.
    """


class SMTPHeloError(SMTPResponseException):
    """
    Server refused HELO or EHLO.
    """


class SMTPDataError(SMTPResponseException):
    """
    Server refused DATA content.
    """


class SMTPAuthenticationError(SMTPResponseException):
    """
    Server refused our AUTH request; may be caused by invalid credentials.
    """


class SMTPSenderRefused(SMTPResponseException):
    """
    SMTP server refused the message sender.
    """

    def __init__(self, code: int, message: str, sender: str, /) -> None:
        self.code = code
        self.message = message
        self.sender = sender
        self.args = (code, message, sender)


class SMTPRecipientRefused(SMTPResponseException):
    """
    SMTP server refused a message recipient.
    """

    def __init__(self, code: int, message: str, recipient: str, /) -> None:
        self.code = code
        self.message = message
        self.recipient = recipient
        self.args = (code, message, recipient)


class SMTPRecipientsRefused(SMTPException):
    """
    SMTP server refused multiple recipients.
    """

    def __init__(self, recipients: list[SMTPRecipientRefused], /) -> None:
        self.recipients = recipients
        self.message = str(recipients)
        self.args = (recipients,)


class SMTPSendError(SMTPException):
    """
    A mail transaction was interrupted by a connection error, timeout, or
    cancellation before the outcome was known.

    Carries the transaction :attr:`stage` reached and the recipients the
    server had already accepted, so callers can decide how to proceed. When
    :attr:`delivery_uncertain` is true, the message may have been delivered
    and should not be resent automatically.
    """

    def __init__(
        self,
        message: str,
        /,
        *,
        stage: SendStage,
        accepted_recipients: Iterable[str] = (),
        refused_recipients: Mapping[str, SMTPResponse] | None = None,
    ) -> None:
        self.stage = stage
        self.accepted_recipients = tuple(accepted_recipients)
        self.refused_recipients = (
            dict(refused_recipients) if refused_recipients is not None else {}
        )
        super().__init__(message)

    @property
    def delivery_uncertain(self) -> bool:
        """
        True if the message content was fully sent but the server's final
        acknowledgement was not received.
        """
        return self.stage is SendStage.CONFIRMATION
