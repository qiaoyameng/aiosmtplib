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
    auth_xoauth2_error_status,
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


def _b64_json(data: object) -> str:
    return base64.b64encode(json.dumps(data).encode("utf-8")).decode("ascii")


@pytest.mark.parametrize(
    "status",
    ["400", "401", "403"],
    ids=["bad request", "invalid token", "insufficient scope"],
)
def test_auth_xoauth2_error_status_valid(status: str) -> None:
    challenge = _b64_json(
        {"status": status, "schemes": "bearer", "scope": "https://mail.google.com/"}
    )

    assert auth_xoauth2_error_status(challenge) == status


def test_auth_xoauth2_error_status_bytes_challenge() -> None:
    challenge = _b64_json({"status": "401"}).encode("ascii")

    assert auth_xoauth2_error_status(challenge) == "401"


@pytest.mark.parametrize(
    "challenge",
    [
        "not base64 at all!!!",
        "",  # empty decodes to empty bytes, not JSON
        _b64_json(["401"]),  # JSON, but not an object
        _b64_json({"error": "401"}),  # no status field
        _b64_json({"status": 401}),  # status is not a string
        _b64_json({"status": None}),
    ],
    ids=[
        "invalid base64",
        "empty",
        "json list",
        "missing status",
        "non-string status",
        "null status",
    ],
)
def test_auth_xoauth2_error_status_invalid_challenge(challenge: str) -> None:
    assert auth_xoauth2_error_status(challenge) is None
