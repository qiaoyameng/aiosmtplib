"""
Authentication related methods.
"""

import base64
import binascii
import hmac
import json

from .errors import SMTPAuthenticationError
from .typing import SMTPStatus

__all__ = (
    "auth_crammd5_verify",
    "auth_login_encode",
    "auth_plain_encode",
    "auth_xoauth2_encode",
    "parse_xoauth2_challenge",
    "is_xoauth2_refreshable",
)

# XOAUTH2 error challenge statuses, per
# https://developers.google.com/gmail/imap/xoauth2-protocol#error_response_2
XOAUTH2_INVALID_TOKEN = "401"
XOAUTH2_INVALID_SCOPE = "403"


def _ensure_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value

    return value.encode("utf-8")


def auth_crammd5_verify(
    username: str | bytes,
    password: str | bytes,
    challenge: str | bytes,
    /,
) -> bytes:
    """
    CRAM-MD5 auth uses the password as a shared secret to MD5 the server's
    response, and sends the username combined with that (base64 encoded).
    """
    username_bytes = _ensure_bytes(username)
    password_bytes = _ensure_bytes(password)
    try:
        decoded_challenge = base64.b64decode(challenge)
    except (binascii.Error, ValueError) as exc:
        raise SMTPAuthenticationError(
            SMTPStatus.auth_continue,
            f"Invalid CRAM-MD5 challenge from server: {challenge!r}",
        ) from exc

    md5_digest = hmac.new(password_bytes, msg=decoded_challenge, digestmod="md5")
    verification = username_bytes + b" " + md5_digest.hexdigest().encode("ascii")
    encoded_verification = base64.b64encode(verification)

    return encoded_verification


def auth_plain_encode(
    username: str | bytes,
    password: str | bytes,
    /,
) -> bytes:
    """
    PLAIN auth base64 encodes the username and password together.
    """
    username_bytes = _ensure_bytes(username)
    password_bytes = _ensure_bytes(password)

    username_and_password = b"\0" + username_bytes + b"\0" + password_bytes
    encoded = base64.b64encode(username_and_password)

    return encoded


def auth_login_encode(
    username: str | bytes,
    password: str | bytes,
    /,
) -> tuple[bytes, bytes]:
    """
    LOGIN auth base64 encodes the username and password and sends them
    in sequence.
    """
    username_bytes = _ensure_bytes(username)
    password_bytes = _ensure_bytes(password)

    encoded_username = base64.b64encode(username_bytes)
    encoded_password = base64.b64encode(password_bytes)

    return encoded_username, encoded_password


def auth_xoauth2_encode(
    username: str | bytes,
    access_token: str | bytes,
    /,
) -> bytes:
    """
    XOAUTH2 auth encodes the username and OAuth2 access token per
    https://developers.google.com/gmail/imap/xoauth2-protocol

    Format: base64("user=" + username + "\\x01auth=Bearer " + token + "\\x01\\x01")
    """
    username_bytes = _ensure_bytes(username)
    token_bytes = _ensure_bytes(access_token)

    auth_string = (
        b"user=" + username_bytes + b"\x01auth=Bearer " + token_bytes + b"\x01\x01"
    )
    encoded = base64.b64encode(auth_string)

    return encoded


def parse_xoauth2_challenge(challenge: str | bytes, /) -> str | None:
    """
    Decode a base64-encoded XOAUTH2 error challenge and return its ``status``
    value (e.g. ``"401"`` for an expired token, ``"403"`` for insufficient
    scope).

    Returns ``None`` if the challenge is empty, not valid base64, or not a JSON
    object carrying a string status. Protocol-level junk is therefore not
    mistaken for a refreshable credential failure.
    """
    if isinstance(challenge, str):
        challenge = challenge.encode("ascii", errors="ignore")

    if not challenge:
        return None

    try:
        decoded = base64.b64decode(challenge, validate=True)
        payload = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    status = payload.get("status")
    if not isinstance(status, str) or not status:
        return None

    return status


def is_xoauth2_refreshable(exc: SMTPAuthenticationError, /) -> bool:
    """
    Whether an XOAUTH2 authentication failure indicates credentials that can
    be refreshed (a fresh access token may succeed).

    Only an explicit ``401`` invalid-grant challenge that completed the SASL
    exchange (the failure surfaced on the final reply) qualifies. A ``403``
    (insufficient scope), a bare ``535`` with no challenge, and protocol or
    transient service errors are deliberately excluded: retrying those with a
    new token cannot help.
    """
    return (
        exc.code == SMTPStatus.auth_failed
        and exc.xoauth2_error == XOAUTH2_INVALID_TOKEN
    )
