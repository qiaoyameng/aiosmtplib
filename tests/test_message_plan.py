"""
Tests for pre-send capability planning (SMTPUTF8/8BITMIME/downgrades).
"""

import email.header
import email.message
from email.message import EmailMessage, Message

import pytest

from aiosmtplib.email import (
    MessageSendPlan,
    PlannedEnvelopeAddress,
    analyze_envelope_address,
    flatten_message,
    plan_message,
)


def make_message(
    sender: str,
    recipient: str,
    body: str = "Hello World",
    *,
    message_class: type[EmailMessage] | type[Message] = EmailMessage,
) -> EmailMessage | Message:
    message = message_class()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "A message"
    if isinstance(message, EmailMessage):
        message.set_content(body)
    else:
        message.set_payload(body)
    return message


@pytest.mark.parametrize(
    "address,is_ascii,local_part,domain,ascii_domain",
    (
        ("alice@example.com", True, "alice", "example.com", "example.com"),
        ("user@例え.jp", True, "user", "例え.jp", "xn--r8jz45g.jp"),
        ("张伟@example.com", False, "张伟", "example.com", "example.com"),
        ("张伟@例え.jp", False, "张伟", "例え.jp", "xn--r8jz45g.jp"),
        ("user@[127.0.0.1]", True, "user", "[127.0.0.1]", "[127.0.0.1]"),
        ("bounce", True, "bounce", "", ""),
    ),
    ids=(
        "ascii",
        "idn_domain",
        "non_ascii_local",
        "non_ascii_local_idn",
        "address_literal",
        "no_domain",
    ),
)
def test_analyze_envelope_address(
    address: str,
    is_ascii: bool,
    local_part: str,
    domain: str,
    ascii_domain: str | None,
) -> None:
    planned = analyze_envelope_address(address)

    assert isinstance(planned, PlannedEnvelopeAddress)
    assert planned.original == address
    assert planned.local_part == local_part
    assert planned.domain == domain
    assert planned.ascii_domain == ascii_domain
    assert planned.is_ascii is is_ascii


def test_idn_domain_downgrades_to_a_label() -> None:
    planned = analyze_envelope_address("user@例え.jp")

    assert planned.is_ascii is True
    assert planned.downgraded_address == "user@xn--r8jz45g.jp"


def test_non_ascii_local_part_cannot_be_downgraded() -> None:
    planned = analyze_envelope_address("张伟@example.com")

    assert planned.is_ascii is False
    assert planned.downgraded_address is None

    with pytest.raises(UnicodeEncodeError):
        plan = MessageSendPlan(
            sender=planned, recipients=(analyze_envelope_address("bob@example.org"),)
        )
        plan.envelope(smtputf8=False)


def test_chinese_display_name_does_not_require_smtputf8() -> None:
    message = make_message(
        "张伟 <zhang.wei@example.com>", "李四 <lisi@example.org>"
    )

    plan = plan_message(message)

    assert plan.utf8_required is False
    assert plan.envelope_requires_utf8 is False
    assert plan.addresses_requiring_utf8 == frozenset()
    assert plan.idn_addresses == frozenset()
    assert plan.headers_encoded is True
    assert "mime-headers" in plan.downgrades

    sender, recipients = plan.envelope(smtputf8=False)
    assert sender == "zhang.wei@example.com"
    assert recipients == ("lisi@example.org",)

    flat = flatten_message(message, utf8=False, cte_type="7bit")
    assert b"=?utf-8?" in flat
    assert flat.isascii()


def test_internationalized_domain_downgrades_with_idna() -> None:
    message = make_message("user@例え.jp", "bob@example.org")

    plan = plan_message(message)

    assert plan.utf8_required is False
    assert plan.idn_addresses == frozenset({"user@例え.jp"})
    assert "idna" in plan.downgrades

    sender, recipients = plan.envelope(smtputf8=False)
    assert sender == "user@xn--r8jz45g.jp"
    assert recipients == ("bob@example.org",)

    sender, recipients = plan.envelope(smtputf8=True)
    assert sender == "user@例え.jp"

    flat = flatten_message(
        message,
        utf8=False,
        cte_type="7bit",
        ascii_addresses={"user@例え.jp": "user@xn--r8jz45g.jp"},
    )
    assert b"user@xn--r8jz45g.jp" in flat
    assert flat.isascii()


def test_non_ascii_local_part_requires_smtputf8() -> None:
    message = make_message("张伟@example.com", "bob@example.org")

    plan = plan_message(message)

    assert plan.utf8_required is True
    assert plan.envelope_requires_utf8 is True
    assert plan.addresses_requiring_utf8 == frozenset({"张伟@example.com"})
    assert plan.idn_addresses == frozenset()

    with pytest.raises(UnicodeEncodeError):
        plan.envelope(smtputf8=False)

    sender, recipients = plan.envelope(smtputf8=True)
    assert sender == "张伟@example.com"
    assert recipients == ("bob@example.org",)


def test_pure_ascii_envelope_needs_no_extensions() -> None:
    message = make_message("alice@example.com", "bob@example.org")

    plan = plan_message(message)

    assert plan.utf8_required is False
    assert plan.headers_encoded is False
    assert plan.body_8bit is False
    assert plan.downgrades == frozenset()

    sender, recipients = plan.envelope(smtputf8=False)
    assert sender == "alice@example.com"
    assert recipients == ("bob@example.org",)


def test_eight_bit_body_is_a_downgrade_not_a_hard_requirement() -> None:
    message = make_message(
        "张伟 <z@example.com>", "李四 <l@example.org>", body="中文正文"
    )

    plan = plan_message(message)

    assert plan.utf8_required is False
    assert plan.body_8bit is True
    assert plan.requires_8bitmime is False
    assert "7bit-cte" in plan.downgrades

    flat_seven_bit = flatten_message(message, utf8=False, cte_type="7bit")
    assert flat_seven_bit.isascii()


@pytest.mark.parametrize(
    "message_class", (EmailMessage, Message), ids=("mime", "compat32")
)
def test_plan_supports_both_message_classes(
    message_class: type[EmailMessage] | type[Message],
) -> None:
    message = make_message(
        "张伟 <zhang.wei@example.com>",
        "李四 <lisi@example.org>",
        message_class=message_class,
    )

    plan = plan_message(message)

    assert plan.utf8_required is False
    assert plan.headers_encoded is True


def test_plan_message_compat32_header_object() -> None:
    message = Message()
    message["From"] = email.header.Header(
        "张伟 <zhang.wei@example.com>", "utf-8"
    )
    message["To"] = email.header.Header("李四 <lisi@example.org>", "utf-8")
    message.set_payload("hello")

    plan = plan_message(message)

    assert plan.utf8_required is False
    sender, recipients = plan.envelope(smtputf8=False)
    assert sender == "zhang.wei@example.com"
    assert recipients == ("lisi@example.org",)


def test_plan_message_explicit_sender_and_recipients() -> None:
    message = make_message("header@example.com", "header-recipient@example.org")

    plan = plan_message(
        message,
        sender="张伟@example.net",
        recipients=("bob@例え.jp",),
    )

    assert plan.sender.original == "张伟@example.net"
    assert plan.utf8_required is True
    assert [address.original for address in plan.recipients] == ["bob@例え.jp"]


def test_plan_message_requires_sender_and_recipients() -> None:
    message = EmailMessage()
    message["To"] = "bob@example.org"

    with pytest.raises(ValueError, match="No From"):
        plan_message(message)

    message["From"] = "alice@example.com"
    del message["To"]

    with pytest.raises(ValueError, match="No recipient"):
        plan_message(message)


def test_plan_message_recipient_string_argument() -> None:
    message = make_message("alice@example.com", "header@example.org")

    plan = plan_message(message, recipients="bob@例え.jp")

    assert [address.original for address in plan.recipients] == ["bob@例え.jp"]
    assert plan.idn_addresses == frozenset({"bob@例え.jp"})


def test_analyze_envelope_address_idna_failure_requires_smtputf8() -> None:
    # A domain the IDNA codec rejects can't be downgraded.
    planned = analyze_envelope_address("user@\uffff.jp")

    assert planned.ascii_domain is None
    assert planned.is_ascii is False
    assert planned.downgraded_address is None


def test_plan_message_reply_to_idn_is_downgraded_in_headers() -> None:
    message = make_message("alice@example.com", "bob@example.org")
    message["Reply-To"] = "reply@例え.jp"

    plan = plan_message(message)

    assert plan.utf8_required is False
    flat = flatten_message(
        message,
        utf8=False,
        cte_type="7bit",
        ascii_addresses={"reply@例え.jp": "reply@xn--r8jz45g.jp"},
    )
    assert b"reply@xn--r8jz45g.jp" in flat
    assert flat.isascii()


def test_plan_message_with_no_body_separator() -> None:
    from aiosmtplib.email import _split_headers_body

    headers, body = _split_headers_body(b"Subject: no body")
    assert headers == b"Subject: no body"
    assert body == b""


def test_plan_message_downgrade_flatten_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import aiosmtplib.email as email_module

    def boom(*args: object, **kwargs: object) -> bytes:
        raise email.errors.HeaderWriteError("defect")

    message = make_message("张伟@example.com", "bob@example.org")
    monkeypatch.setattr(email_module, "flatten_message", boom)

    # The UTF-8 flatten also fails with the monkeypatch, so emulate 3.15 only
    # for the downgraded call by counting calls.
    calls = {"n": 0}

    def flaky(*args: object, **kwargs: object) -> bytes:
        calls["n"] += 1
        if calls["n"] == 1:
            raise email.errors.HeaderWriteError("defect")
        return b"From: x\r\n\r\nbody"

    monkeypatch.setattr(email_module, "flatten_message", flaky)
    plan = plan_message(message)

    assert plan.utf8_required is True
    assert plan.headers_encoded is True
