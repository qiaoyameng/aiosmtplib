"""
Pre-send capability planning.

Analyzes the message envelope and headers to decide which ESMTP extensions
(SMTPUTF8, 8BITMIME) a message needs, and which standards based downgrades
(IDNA domains, RFC 2047 header encoding, 7bit body encoding) may be applied
instead.
"""

import dataclasses
import email.message
from collections.abc import Iterable, Sequence

from .email import extract_addresses, flatten_message, parse_address
from .errors import SMTPNotSupported

__all__ = ("SendPlan", "build_send_plan")


ADDRESS_HEADERS = frozenset(
    {
        "from",
        "sender",
        "reply-to",
        "to",
        "cc",
        "bcc",
        "resent-from",
        "resent-sender",
        "resent-to",
        "resent-cc",
        "resent-bcc",
    }
)


@dataclasses.dataclass(frozen=True)
class SendPlan:
    """
    The result of analyzing a message before sending, as returned by
    :meth:`.SMTP.plan_message`.

    ``sender``, ``recipients``, ``mail_options`` and ``message`` are exactly
    what :meth:`.SMTP.send_message` passes on to :meth:`.SMTP.sendmail`.
    ``smtputf8`` and ``eightbitmime`` indicate whether the SMTPUTF8 and
    BODY=8BITMIME parameters will be used, and ``downgrades`` describes the
    standards based downgrades applied to avoid requiring extensions the
    server does not offer.
    """

    sender: str
    recipients: tuple[str, ...]
    mail_options: tuple[str, ...]
    message: bytes
    smtputf8: bool
    eightbitmime: bool
    downgrades: tuple[str, ...]


def _split_address(address: str) -> tuple[str, str]:
    local_part, at_sign, domain = address.rpartition("@")
    if not at_sign:
        return address, ""
    return local_part, domain


def _address_requires_utf8(address: str) -> bool:
    """
    An envelope address needs SMTPUTF8 if its local part is non-ASCII (there
    is no standard encoding for it), or if its domain is non-ASCII and cannot
    be IDNA encoded.
    """
    local_part, domain = _split_address(address)
    if not local_part.isascii():
        return True
    if domain and not domain.isascii():
        try:
            domain.encode("idna")
        except UnicodeError:
            return True
    return False


def _idna_encode_domain(address: str) -> tuple[str, str | None]:
    """
    Downgrade a non-ASCII address domain to its IDNA form, returning the
    rewritten address and a note describing the downgrade.
    """
    local_part, domain = _split_address(address)
    if not domain or domain.isascii():
        return address, None
    idna_domain = domain.encode("idna").decode("ascii")
    note = f"IDNA encoded domain {domain!r} as {idna_domain!r}"
    return f"{local_part}@{idna_domain}", note


def _headers_require_utf8(message: email.message.Message) -> bool:
    """
    Non-ASCII addr-specs in headers require SMTPUTF8: RFC 2047 encoding would
    corrupt them, and rewriting them (e.g. transliterating a local part or
    IDNA encoding a domain) would silently change the message. Non-ASCII
    display names and other header text do not, as the generator encodes
    them per RFC 2047.
    """
    for name, value in message.items():
        if name.lower() not in ADDRESS_HEADERS:
            continue
        for address in extract_addresses(value):
            if not address.isascii():
                return True
    return False


def _headers_have_non_ascii_text(message: email.message.Message) -> bool:
    return any(not str(value).isascii() for value in message.values())


def build_send_plan(
    message: email.message.EmailMessage | email.message.Message,
    /,
    *,
    sender: str,
    recipients: Sequence[str],
    mail_options: Iterable[str] | None = None,
    smtputf8_supported: bool = False,
    eightbitmime_supported: bool = False,
) -> SendPlan:
    """
    Work out how a message must be sent with the given server capabilities.

    The same rules are applied by :meth:`.SMTP.send_message`, so a plan
    always matches what sending would do.

    :raises ValueError: on an address that can't be safely sent
    :raises SMTPNotSupported: if the message requires SMTPUTF8, but the
        server does not support it
    """
    options = list(mail_options) if mail_options else []
    sender = parse_address(sender)
    recipients = [parse_address(recipient) for recipient in recipients]

    utf8_required = (
        _address_requires_utf8(sender)
        or any(_address_requires_utf8(recipient) for recipient in recipients)
        or _headers_require_utf8(message)
    )

    downgrades: list[str] = []
    if utf8_required:
        if not smtputf8_supported:
            raise SMTPNotSupported(
                "The message envelope or headers contain non-ASCII characters "
                "that require SMTPUTF8, but SMTPUTF8 is not supported by this "
                "server"
            )
        planned_sender = sender
        planned_recipients = tuple(recipients)
        if "smtputf8" not in [option.lower() for option in options]:
            options.append("SMTPUTF8")
    else:
        planned_sender, sender_downgrade = _idna_encode_domain(sender)
        if sender_downgrade is not None:
            downgrades.append(sender_downgrade)
        planned_recipient_list = []
        for recipient in recipients:
            planned_recipient, recipient_downgrade = _idna_encode_domain(recipient)
            if recipient_downgrade is not None:
                downgrades.append(recipient_downgrade)
            planned_recipient_list.append(planned_recipient)
        planned_recipients = tuple(planned_recipient_list)
        if _headers_have_non_ascii_text(message):
            downgrades.append("Non-ASCII header content will be RFC 2047 encoded")

    if eightbitmime_supported:
        if "body=8bitmime" not in [option.lower() for option in options]:
            options.append("BODY=8BITMIME")
        cte_type = "8bit"
    else:
        cte_type = "7bit"

    flat_message = flatten_message(message, utf8=utf8_required, cte_type=cte_type)

    if cte_type == "7bit":
        eightbit_message = flatten_message(message, utf8=utf8_required, cte_type="8bit")
        if not eightbit_message.isascii():
            downgrades.append(
                "8BITMIME is not supported; the message body will use a 7bit "
                "content-transfer-encoding"
            )

    return SendPlan(
        sender=planned_sender,
        recipients=planned_recipients,
        mail_options=tuple(options),
        message=flat_message,
        smtputf8=utf8_required,
        eightbitmime=eightbitmime_supported,
        downgrades=tuple(downgrades),
    )
