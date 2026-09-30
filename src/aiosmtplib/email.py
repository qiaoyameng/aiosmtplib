"""
Email message and address formatting/parsing functions.
"""

import copy
import email.charset
import email.errors
import email.generator
import email.header
import email.headerregistry
import email.message
import email.policy
import email.utils
import io
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import cast


__all__ = (
    "MessageSendPlan",
    "PlannedEnvelopeAddress",
    "extract_recipients",
    "extract_sender",
    "flatten_message",
    "parse_address",
    "plan_message",
    "quote_address",
)


SPECIALS_REGEX = re.compile(r'[][\\()<>@,:;".]')
ESCAPES_REGEX = re.compile(r'[\\"]')
UTF8_CHARSET = email.charset.Charset("utf-8")
# Characters that would end the address on an SMTP command line (or start a
# new command), and so can't appear in a mailbox outside of a quoted-string
# local part. Whitespace here includes CR/LF, so this also serves as a first
# line of defence against command injection.
ADDRESS_INJECTION_REGEX = re.compile(r'[\s<>"]')
QUOTED_LOCAL_PART_REGEX = re.compile(r'^"(?:[^"\\\r\n]|\\.)*"')


def _validate_address(address: str) -> None:
    """
    Reject addresses that can't be safely placed on an SMTP command line.

    ``email.utils.parseaddr`` is lenient, and will pass through strings that
    contain whitespace or angle brackets; if we sent those as-is, a caller
    supplied address could smuggle extra ESMTP parameters (or commands) into
    the MAIL, RCPT, VRFY and EXPN commands.
    """
    # A quoted-string local part may legitimately contain these characters
    unquoted_address = QUOTED_LOCAL_PART_REGEX.sub("", address, count=1)
    if ADDRESS_INJECTION_REGEX.search(unquoted_address):
        raise ValueError(
            f"Address {address!r} contains characters not permitted in an SMTP mailbox"
        )


def parse_address(address: str) -> str:
    """
    Parse an email address, falling back to the raw string given.

    :raises ValueError: if the parsed address contains characters that
        can't safely be sent on an SMTP command line.
    """
    _, parsed_address = email.utils.parseaddr(address)
    parsed_address = parsed_address or address.strip()

    _validate_address(parsed_address)

    return parsed_address


def quote_address(address: str) -> str:
    """
    Quote a subset of the email addresses defined by RFC 821.
    """
    parsed_address = parse_address(address)
    return f"<{parsed_address}>"


# Headers that carry mailbox addresses; rewritten to A-labels when an IDN
# domain has to be downgraded for a server without SMTPUTF8.
ADDRESS_HEADERS: tuple[tuple[str, str], ...] = (
    ("Sender", "Resent-Sender"),
    ("From", "Resent-From"),
    ("Reply-To", "Resent-Reply-To"),
    ("To", "Resent-To"),
    ("Cc", "Resent-Cc"),
    ("Bcc", "Resent-Bcc"),
)


@dataclass(frozen=True)
class PlannedEnvelopeAddress:
    """
    A single envelope mailbox, analysed for internationalisation.

    :param original: the address as supplied, with the local part in Unicode.
    :param local_part: everything before the last ``@``.
    :param domain: everything after the last ``@``, in Unicode (U-label form).
    :param ascii_domain: the IDNA-encoded (A-label) domain, or None if the
        domain is an address literal, is already ASCII, or can't be encoded.
    :param non_ascii_local_part: True if the local part is not ASCII; only the
        SMTPUTF8 extension can carry such an address - it may not be downgraded.
    """

    original: str
    local_part: str
    domain: str
    ascii_domain: str | None = None
    non_ascii_local_part: bool = False

    @property
    def is_ascii(self) -> bool:
        """True if the whole address can be sent on a 7-bit ASCII command line."""
        return self.ascii_domain is not None and not self.non_ascii_local_part

    @property
    def downgraded_address(self) -> str | None:
        """The IDNA-downgraded mailbox, or None if no downgrade is possible."""
        if self.non_ascii_local_part or self.ascii_domain is None:
            return None
        if self.ascii_domain == self.domain:
            return self.original
        return f"{self.local_part}@{self.ascii_domain}"


def analyze_envelope_address(address: str) -> PlannedEnvelopeAddress:
    """
    Split a mailbox into local part/domain and determine its downgrade path.
    """
    if "@" not in address:
        local_part, domain = address, ""
    else:
        local_part, domain = address.rsplit("@", 1)

    try:
        local_part.encode("ascii")
    except UnicodeEncodeError:
        non_ascii_local_part = True
    else:
        non_ascii_local_part = False

    ascii_domain: str | None = None
    # Address literals (e.g. user@[127.0.0.1]) and domains with no labels to
    # encode are passed through as-is.
    if domain and not domain.startswith("["):
        try:
            ascii_domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_domain = None

    if ascii_domain is None:
        try:
            address.encode("ascii")
        except UnicodeEncodeError:
            # An un-encodable non-ASCII domain is no more downgradeable than a
            # non-ASCII local part.
            non_ascii_local_part = True
        else:
            ascii_domain = domain

    return PlannedEnvelopeAddress(
        original=address,
        local_part=local_part,
        domain=domain,
        ascii_domain=ascii_domain,
        non_ascii_local_part=non_ascii_local_part,
    )


@dataclass(frozen=True)
class MessageSendPlan:
    """
    Pre-send analysis of a message's envelope and serialized headers/body.

    The same plan drives :meth:`SMTP.send_message`, so analysis and transmission
    can never disagree.

    :param sender: the envelope sender (MAIL FROM), as extracted from the message.
    :param recipients: envelope recipients (RCPT TO), in order.
    :param utf8_required: True if an internationalized local part (or otherwise
        un-downgradeable address) requires the SMTPUTF8 extension. Sending MUST
        fail before MAIL if the server doesn't advertise it; such addresses are
        never silently transliterated.
    :param addresses_requiring_utf8: envelope mailboxes that force SMTPUTF8.
    :param idn_addresses: envelope mailboxes whose non-ASCII domain can be
        downgraded to A-labels (IDNA) without SMTPUTF8.
    :param headers_encoded: True if non-ASCII header text (display names etc.)
        is carried as MIME encoded-words, which is plain ASCII on the wire.
    :param body_8bit: True if the serialized message body contains octets
        outside 7-bit ASCII; it can go out as BODY=8BITMIME, or be downgraded to
        a 7-bit content transfer encoding.
    :param downgrades: downgrades actually applied when sending without
        SMTPUTF8/8BITMIME, for diagnostics.
    """

    sender: PlannedEnvelopeAddress
    recipients: tuple[PlannedEnvelopeAddress, ...]
    utf8_required: bool = False
    addresses_requiring_utf8: frozenset[str] = field(default_factory=frozenset)
    idn_addresses: frozenset[str] = field(default_factory=frozenset)
    ascii_address_map: dict[str, str] = field(default_factory=dict)
    headers_encoded: bool = False
    body_8bit: bool = False
    downgrades: frozenset[str] = field(default_factory=frozenset)

    @property
    def envelope_requires_utf8(self) -> bool:
        """True if any envelope mailbox can't be downgraded to ASCII."""
        return not self.sender.is_ascii or any(
            not recipient.is_ascii for recipient in self.recipients
        )

    @property
    def requires_8bitmime(self) -> bool:
        """
        True only if the body is 8-bit and can't be carried via a 7-bit CTE.

        The standard library generator always provides the 7-bit fallback, so
        8BITMIME is an optimization, never a hard requirement.
        """
        return False

    def envelope(self, *, smtputf8: bool) -> tuple[str, tuple[str, ...]]:
        """
        Return the ``(sender, recipients)`` mailbox strings to actually send.

        With SMTPUTF8 the original Unicode mailboxes are used; without it IDN
        domains are downgraded to A-labels.
        """
        if smtputf8:
            return self.sender.original, tuple(
                recipient.original for recipient in self.recipients
            )

        downgraded_sender = self.sender.downgraded_address
        downgraded_recipients = tuple(
            recipient.downgraded_address for recipient in self.recipients
        )
        if downgraded_sender is None or any(
            recipient is None for recipient in downgraded_recipients
        ):
            undowngradeable = [
                address.original
                for address in (self.sender, *self.recipients)
                if not address.is_ascii
            ]
            raise UnicodeEncodeError(
                "idna",
                ",".join(undowngradeable),
                0,
                1,
                "non-ASCII local part can't be sent without SMTPUTF8",
            )
        return downgraded_sender, cast(tuple[str, ...], downgraded_recipients)


def _rewrite_address_headers(
    message: email.message.EmailMessage | email.message.Message,
    ascii_addresses: dict[str, str],
) -> None:
    """
    Rewrite envelope address headers, substituting IDNA A-label domains.

    Only addresses actually present in the envelope are rewritten, so headers
    and the MAIL/RCPT command line stay in sync. Display names are preserved.
    """
    for header_name, resent_header_name in ADDRESS_HEADERS:
        for current_name in (header_name, resent_header_name):
            for header in message.get_all(current_name, failobj=[]):
                parsed = email.utils.getaddresses([str(header)])
                rewritten = [
                    (display_name, ascii_addresses.get(address, address))
                    for display_name, address in parsed
                    if address
                ]
                value = ", ".join(
                    email.utils.formataddr(pair) for pair in rewritten
                )
                message.replace_header(current_name, value)


def _prepare_message_copy(
    message: email.message.EmailMessage | email.message.Message,
    *,
    ascii_addresses: dict[str, str] | None = None,
) -> email.message.EmailMessage | email.message.Message:
    message_copy = copy.copy(message)
    del message_copy["Bcc"]
    del message_copy["Resent-Bcc"]

    if ascii_addresses:
        _rewrite_address_headers(message_copy, ascii_addresses)

    return message_copy


def flatten_message(
    message: email.message.EmailMessage | email.message.Message,
    /,
    *,
    utf8: bool = False,
    cte_type: str = "8bit",
    ascii_addresses: dict[str, str] | None = None,
) -> bytes:
    # Make a local copy so we can delete the bcc headers and, when downgrading
    # an IDN domain, rewrite address headers without touching the caller's
    # message.
    message_copy = _prepare_message_copy(message, ascii_addresses=ascii_addresses)

    with io.BytesIO() as messageio:
        if isinstance(message_copy, email.message.EmailMessage):
            policy = email.policy.SMTPUTF8 if utf8 else email.policy.SMTP

            if cte_type != "8bit":
                policy = policy.clone(cte_type=cte_type)

            generator = email.generator.BytesGenerator(messageio, policy=policy)
            generator.flatten(message_copy)
        else:
            # Old message class, Compat32 policy. Compat32 cannot use UTF8
            # Mypy can't handle message unions, so just use different vars
            compat_policy = email.policy.compat32
            if cte_type != "8bit":
                compat_policy = compat_policy.clone(cte_type=cte_type)

            compat_generator = email.generator.BytesGenerator(
                messageio, policy=compat_policy
            )
            compat_generator.flatten(message_copy)

        flat_message = messageio.getvalue()

    return flat_message


def extract_addresses(
    header: str | email.headerregistry.AddressHeader | email.header.Header,
    /,
) -> list[str]:
    """
    Convert address headers into raw email addresses, suitable for use in
    low level SMTP commands.
    """
    addresses: list[str] = []
    if isinstance(header, email.headerregistry.AddressHeader):
        # If the object has been assigned an iterable, it's possible to get a string here.
        header_addresses = cast(
            Iterable[str | email.headerregistry.Address], header.addresses
        )
        for address in header_addresses:
            if isinstance(address, email.headerregistry.Address):
                addresses.append(address.addr_spec)
            else:
                addresses.append(parse_address(address))
    elif isinstance(header, email.header.Header):
        for address_bytes, charset in email.header.decode_header(header):
            address_str = str(address_bytes, encoding=charset or "ascii")
            addresses.append(parse_address(address_str))
    else:
        addresses.extend(addr for _, addr in email.utils.getaddresses([header]))

    return addresses


def extract_sender(
    message: email.message.EmailMessage | email.message.Message,
    /,
) -> str | None:
    """
    Extract the sender from the message object given.
    """
    resent_dates = message.get_all("Resent-Date")

    if resent_dates is not None and len(resent_dates) > 1:
        raise ValueError("Message has more than one 'Resent-' header block")
    elif resent_dates:
        sender_header_name = "Resent-Sender"
        from_header_name = "Resent-From"
    else:
        sender_header_name = "Sender"
        from_header_name = "From"

    # Prefer the sender field per RFC 2822:3.6.2.
    if sender_header_name in message:
        sender_header = message[sender_header_name]
    else:
        sender_header = message[from_header_name]

    if sender_header is None:
        return None

    addresses = extract_addresses(sender_header)
    if not addresses:
        return None

    return addresses[0]


def extract_recipients(
    message: email.message.EmailMessage | email.message.Message,
    /,
) -> list[str]:
    """
    Extract the recipients from the message object given.
    """
    recipients: list[str] = []

    resent_dates = message.get_all("Resent-Date")

    if resent_dates is not None and len(resent_dates) > 1:
        raise ValueError("Message has more than one 'Resent-' header block")
    elif resent_dates:
        recipient_headers = ("Resent-To", "Resent-Cc", "Resent-Bcc")
    else:
        recipient_headers = ("To", "Cc", "Bcc")

    for header in recipient_headers:
        for recipient in message.get_all(header, failobj=[]):
            recipients.extend(extract_addresses(recipient))

    return recipients


def _contains_non_ascii(data: bytes) -> bool:
    return any(byte > 127 for byte in data)


def _split_headers_body(flat_message: bytes) -> tuple[bytes, bytes]:
    # RFC 5322: headers and body are separated by an empty line.
    for separator in (b"\r\n\r\n", b"\n\n"):
        if separator in flat_message:
            headers, _, body = flat_message.partition(separator)
            return headers, body
    return flat_message, b""


def _encoded_word_present(headers: bytes) -> bool:
    return b"=?" in headers

def _header_address_specs(
    message: email.message.EmailMessage | email.message.Message,
) -> list[str]:
    """Collect every mailbox addr-spec appearing in an address header."""
    addresses: list[str] = []
    for header_name, resent_header_name in ADDRESS_HEADERS:
        for current_name in (header_name, resent_header_name):
            for header in message.get_all(current_name, failobj=[]):
                addresses.extend(
                    address for _, address in email.utils.getaddresses([str(header)])
                )
    return addresses


def plan_message(
    message: email.message.EmailMessage | email.message.Message,
    /,
    *,
    sender: str | None = None,
    recipients: Iterable[str] | None = None,
) -> MessageSendPlan:
    """
    Analyse a message before sending, and report the ESMTP capabilities it needs.

    This is the single source of truth used by :meth:`SMTP.send_message`: the
    checks performed here are exactly the ones applied during transmission.

    The analysis covers three layers:

    * The *envelope* (MAIL FROM/RCPT TO). A non-ASCII local part requires the
      SMTPUTF8 extension and is never silently rewritten or transliterated; if
      the server lacks SMTPUTF8, sending must fail before MAIL. A non-ASCII
      domain can instead be downgraded with IDNA.
    * The serialized *headers*. Non-ASCII display names and header text are
      folded into ASCII MIME encoded-words, so a Chinese display name by itself
      does not require SMTPUTF8.
    * The serialized *body*. 8-bit content can use 8BITMIME, or be downgraded to
      a 7-bit content transfer encoding, so 8BITMIME is never mandatory.

    :raises ValueError: if no sender/recipient can be determined.
    """
    if sender is None:
        sender = extract_sender(message)
    if sender is None:
        raise ValueError("No From header provided in message")

    if recipients is None:
        recipient_list = extract_recipients(message)
    elif isinstance(recipients, str):
        recipient_list = [recipients]
    else:
        recipient_list = list(recipients)
    if not recipient_list:
        raise ValueError("No recipient headers provided in message")

    planned_sender = analyze_envelope_address(parse_address(sender))
    planned_recipients = tuple(
        analyze_envelope_address(parse_address(recipient))
        for recipient in recipient_list
    )
    envelope_addresses = (planned_sender, *planned_recipients)

    requiring_utf8 = {
        address.original for address in envelope_addresses if not address.is_ascii
    }
    idn_addresses = {
        address.original
        for address in envelope_addresses
        if address.is_ascii and address.ascii_domain != address.domain
    }

    # Addresses carried only in headers (Reply-To, etc.) still dictate whether
    # the message content itself needs SMTPUTF8, and their IDN domains must be
    # downgraded in the serialized headers.
    header_addresses = {
        planned
        for spec in _header_address_specs(message)
        for planned in (analyze_envelope_address(parse_address(spec)),)
    }
    requiring_utf8.update(
        address.original for address in header_addresses if not address.is_ascii
    )

    downgrade_map: dict[str, str] = {}
    for address in (*envelope_addresses, *header_addresses):
        downgraded = address.downgraded_address
        if downgraded is not None and downgraded != address.original:
            downgrade_map[address.original] = downgraded

    # The downgraded rendering: 7-bit policy, A-label address headers. If this
    # serializes to pure ASCII headers, no SMTPUTF8 is needed for content.
    try:
        downgraded_flat = flatten_message(
            message, utf8=False, cte_type="7bit", ascii_addresses=downgrade_map
        )
    except email.errors.MessageError:
        # Newer Pythons refuse to emit the (invalid) encoded-word form of a
        # non-ASCII local part instead of producing broken headers.
        downgraded_flat = None

    if downgraded_flat is not None:
        downgraded_headers, _ = _split_headers_body(downgraded_flat)
        headers_need_utf8 = _contains_non_ascii(downgraded_headers)
        headers_encoded = _encoded_word_present(downgraded_headers)
    else:
        headers_need_utf8 = True
        headers_encoded = True

    # The UTF-8/8bit rendering shows what the message looks like without any
    # downgrade: raw UTF-8 headers (instead of encoded-words) and the natural
    # 8-bit body.
    utf8_flat = flatten_message(message, utf8=True, cte_type="8bit")
    utf8_headers, utf8_body = _split_headers_body(utf8_flat)
    body_8bit = _contains_non_ascii(utf8_body)

    utf8_required = bool(requiring_utf8) or headers_need_utf8

    downgrades: set[str] = set()
    if idn_addresses:
        downgrades.add("idna")
    if headers_encoded and _contains_non_ascii(utf8_headers):
        downgrades.add("mime-headers")
    if body_8bit:
        downgrades.add("7bit-cte")

    return MessageSendPlan(
        sender=planned_sender,
        recipients=planned_recipients,
        utf8_required=utf8_required,
        addresses_requiring_utf8=frozenset(requiring_utf8),
        idn_addresses=frozenset(idn_addresses),
        ascii_address_map=downgrade_map,
        headers_encoded=headers_encoded,
        body_8bit=body_8bit,
        downgrades=frozenset(downgrades),
    )
