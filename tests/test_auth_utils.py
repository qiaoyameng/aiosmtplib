"""
Tests for authentication encoding utils.
"""

import base64
import hmac
import json

import pytest
from hypothesis import given
from hypothesis.strategies import binary, text

from aiosmtplib.auth import (
    auth_crammd5_verify,
    auth_login_encode,
    auth_plain_encode,
    auth_xoauth2_encode,
    is_xoauth2_refreshable,
    parse_xoauth2_challenge,
)
from aiosmtplib.errors import SMTPAuthenticationError
from aiosmtplib.typing import SMTPStatus


@given(binary(), binary(), binary())
def test_auth_crammd5_verify_bytes(
    username: bytes,
    password: bytes,
    challenge: bytes,
) -> None:
    encoded_challenge = base64.b64encode(challenge)

    # Basically a re-implementation of the function being tested :(
    md5_digest = hmac.new(password, msg=challenge, digestmod="md5")
    verification = username + b" " + md5_digest.hexdigest().encode("ascii")
    encoded_verification = base64.b64encode(verification)

    result = auth_crammd5_verify(username, password, encoded_challenge)

    assert result == encoded_verification


@given(text(), text(), text())
def test_auth_crammd5_verify_str(
    username: str,
    password: str,
    challenge: str,
) -> None:
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    challenge_bytes = challenge.encode("utf-8")
    encoded_challenge = base64.b64encode(challenge_bytes)

    # Basically a re-implementation of the function being tested :(
    md5_digest = hmac.new(password_bytes, msg=challenge_bytes, digestmod="md5")
    verification = username_bytes + b" " + md5_digest.hexdigest().encode("ascii")
    encoded_verification = base64.b64encode(verification)

    result = auth_crammd5_verify(username, password, encoded_challenge)

    assert result == encoded_verification


@pytest.mark.parametrize(
    "challenge",
    ["abc", "not base64!!", b"abc"],
    ids=["bad padding", "bad length", "bytes"],
)
def test_auth_crammd5_verify_invalid_challenge(challenge: str | bytes) -> None:
    with pytest.raises(SMTPAuthenticationError) as excinfo:
        auth_crammd5_verify("username", "password", challenge)

    assert excinfo.value.code == SMTPStatus.auth_continue
    assert "CRAM-MD5" in excinfo.value.message


@given(binary(), binary())
def test_auth_plain_encode_bytes(
    username: bytes,
    password: bytes,
) -> None:
    assert auth_plain_encode(username, password) == base64.b64encode(
        b"\0" + username + b"\0" + password
    )


@given(text(), text())
def test_auth_plain_encode_str(
    username: str,
    password: str,
) -> None:
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")

    assert auth_plain_encode(username, password) == base64.b64encode(
        b"\0" + username_bytes + b"\0" + password_bytes
    )


@given(binary(), binary())
def test_auth_login_encode_bytes(
    username: bytes,
    password: bytes,
) -> None:
    assert auth_login_encode(username, password) == (
        base64.b64encode(username),
        base64.b64encode(password),
    )


@given(text(), text())
def test_auth_login_encode_str(
    username: str,
    password: str,
) -> None:
    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")

    assert auth_login_encode(username, password) == (
        base64.b64encode(username_bytes),
        base64.b64encode(password_bytes),
    )


@given(binary(), binary())
def test_auth_xoauth2_encode_bytes(
    username: bytes,
    access_token: bytes,
) -> None:
    auth_string = b"user=" + username + b"\x01auth=Bearer " + access_token + b"\x01\x01"
    assert auth_xoauth2_encode(username, access_token) == base64.b64encode(auth_string)


@given(text(), text())
def test_auth_xoauth2_encode_str(
    username: str,
    access_token: str,
) -> None:
    username_bytes = username.encode("utf-8")
    token_bytes = access_token.encode("utf-8")

    auth_string = (
        b"user=" + username_bytes + b"\x01auth=Bearer " + token_bytes + b"\x01\x01"
    )
    assert auth_xoauth2_encode(username, access_token) == base64.b64encode(auth_string)


def test_auth_xoauth2_encode_known_value() -> None:
    """Test against the example from Google's XOAUTH2 documentation."""
    username = "someuser@example.com"
    token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg"

    result = auth_xoauth2_encode(username, token)

    # Decode and verify the structure
    decoded = base64.b64decode(result)
    assert decoded == (
        b"user=someuser@example.com\x01"
        b"auth=Bearer ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg\x01\x01"
    )


@pytest.mark.parametrize(
    ("status", "extra"),
    [
        ("401", {}),
        ("403", {}),
        ("400", {"schemes": "Bearer"}),
        ("invalid_token", {"scope": "https://mail.google.com/"}),
    ],
)
def test_parse_xoauth2_challenge_valid(status: str, extra: dict) -> None:
    payload = {"status": status, **extra}
    challenge = base64.b64encode(json.dumps(payload).encode())
    assert parse_xoauth2_challenge(challenge) == status


def test_parse_xoauth2_challenge_accepts_str() -> None:
    encoded = base64.b64encode(b'{"status": "401"}').decode("ascii")
    assert parse_xoauth2_challenge(encoded) == "401"


@pytest.mark.parametrize(
    "challenge",
    [
        "",
        "not base64!",
        base64.b64encode(b"not json"),
        base64.b64encode(b"["),
        base64.b64encode(b'"a string"'),
        base64.b64encode(b"[1, 2]"),
        base64.b64encode(b'{"other": "field"}'),
        base64.b64encode(b'{"status": 401}'),
        base64.b64encode(b'{"status": ""}'),
        b"\x01\x02",
    ],
)
def test_parse_xoauth2_challenge_invalid_returns_none(
    challenge: str | bytes,
) -> None:
    assert parse_xoauth2_challenge(challenge) is None


def test_is_xoauth2_refreshable() -> None:
    refreshable = SMTPAuthenticationError(
        SMTPStatus.auth_failed, "bad", xoauth2_error="401"
    )
    assert is_xoauth2_refreshable(refreshable)

    wrong_scope = SMTPAuthenticationError(
        SMTPStatus.auth_failed, "bad", xoauth2_error="403"
    )
    assert not is_xoauth2_refreshable(wrong_scope)

    bare_failure = SMTPAuthenticationError(SMTPStatus.auth_failed, "bad")
    assert not is_xoauth2_refreshable(bare_failure)

    wrong_code = SMTPAuthenticationError(
        SMTPStatus.error_processing, "bad", xoauth2_error="401"
    )
    assert not is_xoauth2_refreshable(wrong_code)
