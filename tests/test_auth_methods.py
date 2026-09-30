"""
Tests for auth methods on the SMTP class.
"""

import asyncio
import base64
import json

import pytest

from aiosmtplib import SMTP
from aiosmtplib.auth import (
    auth_crammd5_verify,
    auth_login_encode,
    auth_plain_encode,
    auth_xoauth2_encode,
)
from aiosmtplib.errors import SMTPAuthenticationError, SMTPException
from aiosmtplib.response import SMTPResponse
from aiosmtplib.typing import SMTPStatus

from .auth import DummySMTPAuth


SUCCESS_RESPONSE = SMTPResponse(SMTPStatus.auth_successful, "OK")
FAILURE_RESPONSE = SMTPResponse(SMTPStatus.auth_failed, "Nope")

CREDENTIALS = [
    ("test", "test"),
    ("admin124", "$3cr3t$"),
    ("føø", "bär€"),
    ("ภาษา".encode("tis-620"), "ไทย".encode("tis-620")),
]
CREDENTIAL_IDS = ["test user", "admin user", "utf-8 user", "tis-620 bytes user"]


async def test_login_without_extension_raises_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.esmtp_extensions = {}

    with pytest.raises(SMTPException) as excinfo:
        await mock_auth.login("username", "bogus")

    assert "Try connecting via TLS" not in excinfo.value.args[0]


async def test_login_unknown_method_raises_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.AUTH_METHODS = ("fakeauth",)
    mock_auth.server_auth_methods = ["fakeauth"]

    with pytest.raises(RuntimeError):
        await mock_auth.login("username", "bogus")


async def test_login_without_method_raises_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.server_auth_methods = []

    with pytest.raises(SMTPException):
        await mock_auth.login("username", "bogus")


async def test_login_tries_all_methods(mock_auth: DummySMTPAuth) -> None:
    responses = [
        FAILURE_RESPONSE,  # CRAM-MD5
        FAILURE_RESPONSE,  # PLAIN
        (SMTPStatus.auth_continue, "VXNlcm5hbWU6"),  # LOGIN continue
        SUCCESS_RESPONSE,  # LOGIN success
    ]
    mock_auth.responses.extend(responses)
    await mock_auth.login("username", "thirdtimelucky")


async def test_login_all_methods_fail_raises_error(mock_auth: DummySMTPAuth) -> None:
    responses = [
        FAILURE_RESPONSE,  # CRAM-MD5
        FAILURE_RESPONSE,  # PLAIN
        FAILURE_RESPONSE,  # LOGIN
    ]
    mock_auth.responses.extend(responses)
    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.login("username", "bogus")


@pytest.mark.parametrize("username,password", CREDENTIALS, ids=CREDENTIAL_IDS)
async def test_auth_plain_success(
    mock_auth: DummySMTPAuth, username: str | bytes, password: str | bytes
) -> None:
    """
    Check that auth_plain base64 encodes the username/password given.
    """
    mock_auth.responses.append(SUCCESS_RESPONSE)
    await mock_auth.auth_plain(username, password)

    encoded = auth_plain_encode(username, password)
    assert mock_auth.received_commands == [b"AUTH PLAIN " + encoded]


async def test_auth_plain_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.responses.append(FAILURE_RESPONSE)

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_plain("username", "bogus")


@pytest.mark.parametrize("username,password", CREDENTIALS, ids=CREDENTIAL_IDS)
async def test_auth_login_success(
    mock_auth: DummySMTPAuth, username: str | bytes, password: str | bytes
) -> None:
    continue_response = (SMTPStatus.auth_continue, "VXNlcm5hbWU6")
    mock_auth.responses.extend([continue_response, SUCCESS_RESPONSE])
    await mock_auth.auth_login(username, password)

    encoded_username, encoded_password = auth_login_encode(username, password)

    assert mock_auth.received_commands == [
        b"AUTH LOGIN " + encoded_username,
        encoded_password,
    ]


async def test_auth_login_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.responses.append(FAILURE_RESPONSE)
    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_login("username", "bogus")


async def test_auth_login_continue_error(mock_auth: DummySMTPAuth) -> None:
    continue_response = (SMTPStatus.auth_continue, "VXNlcm5hbWU6")
    mock_auth.responses.extend([continue_response, FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_login("username", "bogus")


@pytest.mark.parametrize("username,password", CREDENTIALS, ids=CREDENTIAL_IDS)
async def test_auth_crammd5_success(
    mock_auth: DummySMTPAuth, username: str | bytes, password: str | bytes
) -> None:
    continue_response = (
        SMTPStatus.auth_continue,
        base64.b64encode(b"secretteststring").decode("utf-8"),
    )
    mock_auth.responses.extend([continue_response, SUCCESS_RESPONSE])
    await mock_auth.auth_crammd5(username, password)

    response_bytes = continue_response[1].encode("utf-8")
    expected_command = auth_crammd5_verify(username, password, response_bytes)

    assert mock_auth.received_commands == [b"AUTH CRAM-MD5", expected_command]


async def test_auth_crammd5_initial_error(mock_auth: DummySMTPAuth) -> None:
    mock_auth.responses.append(FAILURE_RESPONSE)

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_crammd5("username", "bogus")


async def test_auth_crammd5_continue_error(mock_auth: DummySMTPAuth) -> None:
    continue_response = (SMTPStatus.auth_continue, "VXNlcm5hbWU6")
    mock_auth.responses.extend([continue_response, FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_crammd5("username", "bogus")


async def test_auth_crammd5_invalid_challenge_raises_auth_error(
    mock_auth: DummySMTPAuth,
) -> None:
    continue_response = (SMTPStatus.auth_continue, "not base64!!")
    mock_auth.responses.append(continue_response)

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth.auth_crammd5("username", "bogus")

    assert excinfo.value.code == SMTPStatus.auth_continue
    assert "CRAM-MD5" in excinfo.value.message
    assert mock_auth.received_commands == [b"AUTH CRAM-MD5"]


async def test_login_falls_back_after_invalid_crammd5_challenge(
    mock_auth: DummySMTPAuth,
) -> None:
    responses = [
        (SMTPStatus.auth_continue, "not base64!!"),  # CRAM-MD5 bad challenge
        SUCCESS_RESPONSE,  # PLAIN
    ]
    mock_auth.responses.extend(responses)
    await mock_auth.login("username", "secondtimelucky")

    assert mock_auth.received_commands[0] == b"AUTH CRAM-MD5"
    assert mock_auth.received_commands[1].startswith(b"AUTH PLAIN")


async def test_login_without_starttls_exception(
    smtp_client: SMTP,
    smtpd_server: asyncio.AbstractServer,
    auth_username: str,
    auth_password: str,
) -> None:
    async with smtp_client:
        with pytest.raises(SMTPException) as excinfo:
            await smtp_client.login(auth_username, auth_password)

        assert "Try connecting via TLS" in excinfo.value.args[0]


@pytest.mark.parametrize(
    "username,token",
    [
        ("test@example.com", "ya29.token123"),
        ("user@gmail.com", "access_token_here"),
        ("føø@example.com", "bär€_token"),
        (b"user@example.com", b"access_token_bytes"),
    ],
    ids=["test user", "gmail user", "utf-8 user", "bytes user"],
)
async def test_auth_xoauth2_success(
    mock_auth: DummySMTPAuth, username: str | bytes, token: str | bytes
) -> None:
    """Check that auth_xoauth2 base64 encodes the username/token correctly."""
    mock_auth.responses.append(SUCCESS_RESPONSE)
    await mock_auth.auth_xoauth2(username, token)

    encoded = auth_xoauth2_encode(username, token)
    assert mock_auth.received_commands == [b"AUTH XOAUTH2 " + encoded]


async def test_auth_xoauth2_error(mock_auth: DummySMTPAuth) -> None:
    """Check that auth_xoauth2 raises on failure response."""
    mock_auth.responses.append(FAILURE_RESPONSE)

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_xoauth2("user@example.com", "bad_token")


async def test_auth_xoauth2_challenge_error(mock_auth: DummySMTPAuth) -> None:
    """
    Check that auth_xoauth2 handles the error challenge flow.

    On failure, server sends 334 with base64-encoded error JSON,
    client sends empty response, then gets the final 535 error.
    """
    # Server sends error challenge (334), then final error (535)
    challenge_response = (SMTPStatus.auth_continue, "eyJzdGF0dXMiOiI0MDAifQ==")
    mock_auth.responses.extend([challenge_response, FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth.auth_xoauth2("user@example.com", "expired_token")

    # Verify we sent the initial auth and then empty response
    encoded = auth_xoauth2_encode("user@example.com", "expired_token")
    assert mock_auth.received_commands == [b"AUTH XOAUTH2 " + encoded, b""]


async def test_maybe_login_with_oauth_token_generator(mock_auth: DummySMTPAuth) -> None:
    """Test that _maybe_login_on_connect uses oauth_token_generator when provided."""
    mock_auth.server_auth_methods = ["xoauth2", "plain", "login"]
    mock_auth._login_username = "user@example.com"

    async def get_token() -> str:
        return "test_oauth_token"

    mock_auth._oauth_token_generator = get_token
    mock_auth.responses.append(SUCCESS_RESPONSE)

    await mock_auth._maybe_login_on_connect()

    encoded = auth_xoauth2_encode("user@example.com", "test_oauth_token")
    assert mock_auth.received_commands == [b"AUTH XOAUTH2 " + encoded]


async def test_auth_crammd5_passes_timeout(mock_auth: DummySMTPAuth) -> None:
    """
    Test that auth_crammd5 passes timeout to the verification command.

    Both execute_command calls in auth_crammd5 should receive the timeout parameter.
    """
    continue_response = (
        SMTPStatus.auth_continue,
        base64.b64encode(b"challenge").decode("utf-8"),
    )
    mock_auth.responses.extend([continue_response, SUCCESS_RESPONSE])
    await mock_auth.auth_crammd5("user", "pass", timeout=5.0)

    # Both commands should have received the timeout
    assert len(mock_auth.received_kwargs) == 2
    assert mock_auth.received_kwargs[0].get("timeout") == 5.0
    assert mock_auth.received_kwargs[1].get("timeout") == 5.0


def _b64_json_challenge(status: str) -> tuple[int, str]:
    challenge = base64.b64encode(
        json.dumps({"status": status, "schemes": "bearer"}).encode("utf-8")
    ).decode("ascii")
    return (SMTPStatus.auth_continue, challenge)


async def test_auth_xoauth2_multiple_error_challenges(
    mock_auth: DummySMTPAuth,
) -> None:
    """
    Check that auth_xoauth2 answers every error challenge with an empty
    response, terminating the SASL exchange before raising.
    """
    mock_auth.responses.extend(
        [
            _b64_json_challenge("401"),
            _b64_json_challenge("401"),
            FAILURE_RESPONSE,
        ]
    )

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth.auth_xoauth2("user@example.com", "expired_token")

    assert excinfo.value.xoauth2_error_status == "401"
    encoded = auth_xoauth2_encode("user@example.com", "expired_token")
    assert mock_auth.received_commands == [b"AUTH XOAUTH2 " + encoded, b"", b""]


async def test_auth_xoauth2_error_status_on_exception(
    mock_auth: DummySMTPAuth,
) -> None:
    mock_auth.responses.extend([_b64_json_challenge("403"), FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth.auth_xoauth2("user@example.com", "token")

    assert excinfo.value.xoauth2_error_status == "403"


async def test_auth_xoauth2_malformed_challenge_status_none(
    mock_auth: DummySMTPAuth,
) -> None:
    mock_auth.responses.extend(
        [(SMTPStatus.auth_continue, "not base64!!"), FAILURE_RESPONSE]
    )

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth.auth_xoauth2("user@example.com", "token")

    assert excinfo.value.xoauth2_error_status is None


async def test_auth_xoauth2_no_challenge_status_none(
    mock_auth: DummySMTPAuth,
) -> None:
    mock_auth.responses.append(FAILURE_RESPONSE)

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth.auth_xoauth2("user@example.com", "token")

    assert excinfo.value.xoauth2_error_status is None


def _setup_oauth_mock(mock_auth: DummySMTPAuth, tokens: list[str]) -> list[str]:
    """Configure mock_auth for oauth login; returns a list of tokens used."""
    mock_auth.server_auth_methods = ["xoauth2"]
    mock_auth._login_username = "user@example.com"
    tokens_used: list[str] = []

    async def get_token() -> str:
        token = tokens[len(tokens_used)]
        tokens_used.append(token)
        return token

    mock_auth._oauth_token_generator = get_token
    return tokens_used


async def test_oauth_login_refreshes_token_on_401(
    mock_auth: DummySMTPAuth,
) -> None:
    """An expired token (401 challenge + 535) triggers exactly one refresh."""
    tokens_used = _setup_oauth_mock(mock_auth, ["expired_token", "fresh_token"])
    mock_auth.responses.extend(
        [_b64_json_challenge("401"), FAILURE_RESPONSE, SUCCESS_RESPONSE]
    )

    await mock_auth._maybe_login_on_connect()

    assert tokens_used == ["expired_token", "fresh_token"]
    first = auth_xoauth2_encode("user@example.com", "expired_token")
    second = auth_xoauth2_encode("user@example.com", "fresh_token")
    assert mock_auth.received_commands == [
        b"AUTH XOAUTH2 " + first,
        b"",
        b"AUTH XOAUTH2 " + second,
    ]


async def test_oauth_login_no_refresh_on_403(mock_auth: DummySMTPAuth) -> None:
    """Insufficient permissions (403) is not refreshable."""
    tokens_used = _setup_oauth_mock(mock_auth, ["token1", "token2"])
    mock_auth.responses.extend([_b64_json_challenge("403"), FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth._maybe_login_on_connect()

    assert tokens_used == ["token1"]


async def test_oauth_login_no_refresh_on_transient_failure(
    mock_auth: DummySMTPAuth,
) -> None:
    """A transient server error (4xx) never triggers a token refresh."""
    tokens_used = _setup_oauth_mock(mock_auth, ["token1", "token2"])
    mock_auth.responses.append(
        SMTPResponse(SMTPStatus.error_processing, "4.7.0 Try again later")
    )

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth._maybe_login_on_connect()

    assert tokens_used == ["token1"]


async def test_oauth_login_no_refresh_on_malformed_challenge(
    mock_auth: DummySMTPAuth,
) -> None:
    """A protocol error (unparseable challenge) never triggers a refresh."""
    tokens_used = _setup_oauth_mock(mock_auth, ["token1", "token2"])
    mock_auth.responses.extend(
        [(SMTPStatus.auth_continue, "not base64!!"), FAILURE_RESPONSE]
    )

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth._maybe_login_on_connect()

    assert tokens_used == ["token1"]


async def test_oauth_login_refreshes_only_once(mock_auth: DummySMTPAuth) -> None:
    """If the refreshed token is also rejected, the error is raised."""
    tokens_used = _setup_oauth_mock(mock_auth, ["token1", "token2", "token3"])
    mock_auth.responses.extend(
        [
            _b64_json_challenge("401"),
            FAILURE_RESPONSE,
            _b64_json_challenge("401"),
            FAILURE_RESPONSE,
        ]
    )

    with pytest.raises(SMTPAuthenticationError):
        await mock_auth._maybe_login_on_connect()

    assert tokens_used == ["token1", "token2"]


async def test_oauth_login_refresh_failure_propagates(
    mock_auth: DummySMTPAuth,
) -> None:
    """If the token generator itself fails on refresh, that error propagates."""
    mock_auth.server_auth_methods = ["xoauth2"]
    mock_auth._login_username = "user@example.com"
    calls = 0

    async def failing_token_generator() -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "expired_token"
        raise RuntimeError("token service unavailable")

    mock_auth._oauth_token_generator = failing_token_generator
    mock_auth.responses.extend([_b64_json_challenge("401"), FAILURE_RESPONSE])

    with pytest.raises(RuntimeError, match="token service unavailable"):
        await mock_auth._maybe_login_on_connect()

    assert calls == 2


async def test_oauth_login_error_does_not_contain_token(
    mock_auth: DummySMTPAuth,
) -> None:
    """Tokens must never appear in raised exceptions."""
    secret_token = "super-secret-token-12345"
    tokens_used = _setup_oauth_mock(mock_auth, [secret_token])
    mock_auth.responses.extend([_b64_json_challenge("403"), FAILURE_RESPONSE])

    with pytest.raises(SMTPAuthenticationError) as excinfo:
        await mock_auth._maybe_login_on_connect()

    assert tokens_used == [secret_token]
    assert secret_token not in str(excinfo.value)
    assert secret_token not in repr(excinfo.value)
    assert all(secret_token not in str(arg) for arg in excinfo.value.args)
