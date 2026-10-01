"""
PIPELINING (RFC 2920) tests.

These use a raw asyncio server (rather than aiosmtpd) that controls exactly
when responses are sent, so it can prove that the client sends the whole
MAIL/RCPT batch before waiting for any response.
"""

import asyncio
import socket
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio

from aiosmtplib import (
    SMTP,
    SMTPRecipientsRefused,
    SMTPResponseException,
    SMTPSenderRefused,
    SMTPServerDisconnected,
    SMTPStatus,
)
from aiosmtplib.protocol import SMTPProtocol

from .conftest import ConnectProtocol


SENDER = "sender@example.com"
RECIPIENTS = ["rcpt1@example.com", "rcpt2@example.com", "rcpt3@example.com"]
MESSAGE = "Subject: pipelining test\r\n\r\nHello World\r\n"


class PipeliningServer:
    """
    A minimal SMTP server. In pipelining mode it only answers the MAIL/RCPT
    envelope once every expected command has arrived, so a client that waits
    for each response before sending the next command would deadlock.
    """

    def __init__(self) -> None:
        self.pipelining = True
        self.expected_recipients = 0
        self.mail_response = b"250 OK"
        self.rcpt_responses: dict[bytes, bytes] = {}
        self.default_rcpt_response = b"250 OK"
        self.response_delay = 0.0

        self.received_commands: list[bytes] = []
        self.batch_received_before_response = False
        self.mail_response_before_rcpt = False
        self.data_command_received = False
        self.message_data = b""
        self.rset_received = False
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self, hostname: str) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, host=hostname, port=0, family=socket.AF_INET
        )

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        batch: list[bytes] = []
        try:
            await self._send(writer, b"220 testserver ESMTP")
            while True:
                line = await reader.readline()
                if not line:
                    return
                command = line.split(b" ", 1)[0].upper()
                if command == b"EHLO":
                    await self._send_ehlo_response(writer)
                elif command in (b"MAIL", b"RCPT"):
                    batch.append(line.rstrip(b"\r\n"))
                    self.received_commands.append(line.rstrip(b"\r\n"))
                    if self.pipelining:
                        if len(batch) == 1 + self.expected_recipients:
                            # The whole envelope arrived before any response.
                            self.batch_received_before_response = True
                            if self.response_delay:
                                await asyncio.sleep(self.response_delay)
                            for command_line in batch:
                                await self._send(
                                    writer, self._response_for(command_line)
                                )
                            batch.clear()
                    else:
                        if command == b"MAIL":
                            self.mail_response_before_rcpt = not any(
                                queued.startswith(b"RCPT") for queued in batch
                            )
                        await self._send(writer, self._response_for(batch[-1]))
                        batch.clear()
                elif command == b"DATA":
                    await self._handle_data(reader, writer)
                elif command == b"RSET":
                    self.rset_received = True
                    await self._send(writer, b"250 OK")
                elif command == b"QUIT":
                    await self._send(writer, b"221 Bye")
                    return
                else:
                    await self._send(writer, b"502 Command not implemented")
        except (ConnectionError, asyncio.IncompleteReadError):
            return
        finally:
            writer.close()

    async def _send(self, writer: asyncio.StreamWriter, response: bytes) -> None:
        writer.write(response + b"\r\n")
        await writer.drain()

    async def _send_ehlo_response(self, writer: asyncio.StreamWriter) -> None:
        if self.pipelining:
            writer.write(b"250-testserver\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
        else:
            writer.write(b"250-testserver\r\n250 8BITMIME\r\n")
        await writer.drain()

    def _response_for(self, command_line: bytes) -> bytes:
        if command_line.startswith(b"MAIL"):
            return self.mail_response
        address = command_line.split(b"TO:", 1)[1].strip().strip(b"<>")
        return self.rcpt_responses.get(address, self.default_rcpt_response)

    async def _handle_data(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.data_command_received = True
        await self._send(writer, b"354 End data with <CR><LF>.<CR><LF>")
        while True:
            line = await reader.readline()
            if not line:
                return
            if line == b".\r\n":
                break
            self.message_data += line
        await self._send(writer, b"250 OK, message accepted")


@pytest_asyncio.fixture
async def pipelining_server(hostname: str) -> AsyncGenerator[PipeliningServer]:
    server = PipeliningServer()
    await server.start(hostname)

    yield server

    await server.stop()


@pytest.fixture
def pipelining_client(pipelining_server: PipeliningServer, hostname: str) -> SMTP:
    return SMTP(
        hostname=hostname,
        port=pipelining_server.port,
        timeout=5.0,
        start_tls=False,
    )


async def test_sendmail_pipelining_batches_envelope_commands(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)

    async with pipelining_client:
        errors, message_id = await pipelining_client.sendmail(
            SENDER, RECIPIENTS, MESSAGE
        )

    assert errors == {}
    assert message_id == "OK, message accepted"
    # The server only responded once the whole batch had arrived, so the
    # commands must have been in flight together.
    assert pipelining_server.batch_received_before_response
    assert pipelining_server.received_commands == [
        f"MAIL FROM:<{SENDER}>".encode("ascii"),
        *(f"RCPT TO:<{recipient}>".encode("ascii") for recipient in RECIPIENTS),
    ]
    assert pipelining_server.message_data != b""


async def test_sendmail_pipelining_partial_recipient_refusal(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)
    pipelining_server.rcpt_responses[b"rcpt2@example.com"] = b"550 User unknown"

    async with pipelining_client:
        errors, message_id = await pipelining_client.sendmail(
            SENDER, RECIPIENTS, MESSAGE
        )

    # The error is paired with the correct address, and the message is still
    # delivered to the remaining recipients.
    assert set(errors) == {"rcpt2@example.com"}
    assert errors["rcpt2@example.com"].code == SMTPStatus.mailbox_does_not_exist
    assert errors["rcpt2@example.com"].message == "User unknown"
    assert message_id == "OK, message accepted"
    assert pipelining_server.data_command_received


async def test_sendmail_pipelining_all_recipients_refused(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)
    pipelining_server.default_rcpt_response = b"550 Mailbox unavailable"

    async with pipelining_client:
        with pytest.raises(SMTPRecipientsRefused) as excinfo:
            await pipelining_client.sendmail(SENDER, RECIPIENTS, MESSAGE)

        assert {err.recipient for err in excinfo.value.recipients} == set(RECIPIENTS)
        # DATA must not be sent, but the pipelined responses were all
        # collected, so the connection is still usable.
        assert not pipelining_server.data_command_received
        assert pipelining_server.rset_received
        assert pipelining_client.is_connected


async def test_sendmail_pipelining_mail_refused(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)
    pipelining_server.mail_response = b"550 Sender rejected"

    async with pipelining_client:
        with pytest.raises(SMTPSenderRefused) as excinfo:
            await pipelining_client.sendmail(SENDER, RECIPIENTS, MESSAGE)

        assert excinfo.value.sender == SENDER
        assert not pipelining_server.data_command_received
        assert pipelining_server.rset_received

        # No stale responses are left over: a new transaction on the same
        # connection pairs responses correctly.
        pipelining_server.mail_response = b"250 OK"
        pipelining_server.expected_recipients = 1
        errors, message_id = await pipelining_client.sendmail(
            SENDER, RECIPIENTS[0], MESSAGE
        )
        assert errors == {}
        assert message_id == "OK, message accepted"


async def test_sendmail_pipelining_malformed_response_closes_connection(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)
    pipelining_server.rcpt_responses[b"rcpt1@example.com"] = b"not a response"

    async with pipelining_client:
        with pytest.raises(SMTPResponseException):
            await pipelining_client.sendmail(SENDER, RECIPIENTS, MESSAGE)

        # Framing is lost, so the connection cannot be reused safely.
        assert not pipelining_client.is_connected


async def test_sendmail_without_pipelining_support_sends_sequentially(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.pipelining = False

    async with pipelining_client:
        errors, message_id = await pipelining_client.sendmail(
            SENDER, RECIPIENTS, MESSAGE
        )

    assert errors == {}
    assert message_id == "OK, message accepted"
    # MAIL was answered before any RCPT arrived: no batching without the
    # PIPELINING extension.
    assert pipelining_server.mail_response_before_rcpt
    assert not pipelining_server.batch_received_before_response


async def test_sendmail_pipelining_cancel_leaves_no_stale_responses(
    pipelining_server: PipeliningServer, pipelining_client: SMTP
) -> None:
    pipelining_server.expected_recipients = len(RECIPIENTS)
    pipelining_server.response_delay = 30.0

    await pipelining_client.connect()
    await pipelining_client.ehlo()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            pipelining_client.sendmail(SENDER, RECIPIENTS, MESSAGE), 0.1
        )

    # The batch was sent, but the still-pending responses must not be left
    # for the next message: the connection is dropped instead.
    assert pipelining_server.batch_received_before_response
    assert not pipelining_client.is_connected
    assert not pipelining_server.data_command_received

    pipelining_server.response_delay = 0.0
    await pipelining_client.connect()
    errors, message_id = await pipelining_client.sendmail(
        SENDER, RECIPIENTS, MESSAGE
    )
    assert errors == {}
    assert message_id == "OK, message accepted"
    await pipelining_client.quit()


async def test_protocol_pipelined_commands_pair_responses_in_order(
    connect_protocol: ConnectProtocol,
) -> None:
    received: list[bytes] = []

    async def server_callback(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 testserver\r\n")
        await writer.drain()
        # Only respond once all three commands have arrived.
        received.append(await reader.readuntil(b"NOOP 3\r\n"))
        writer.write(b"250 one\r\n")
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(b"250 two\r\n250 three\r\n")
        await writer.drain()
        writer.close()

    protocol = await connect_protocol(server_callback)
    await protocol.read_response(timeout=1.0)

    responses = await protocol.execute_pipelined_commands(
        [b"NOOP 1", b"NOOP 2", b"NOOP 3"], timeout=1.0
    )

    assert [response.message for response in responses] == ["one", "two", "three"]
    assert received == [b"NOOP 1\r\nNOOP 2\r\nNOOP 3\r\n"]


async def test_protocol_pipelined_commands_empty(
    connect_protocol: ConnectProtocol,
) -> None:
    async def server_callback(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 testserver\r\n")
        await writer.drain()
        writer.close()

    protocol = await connect_protocol(server_callback)
    await protocol.read_response(timeout=1.0)

    assert await protocol.execute_pipelined_commands([], timeout=1.0) == []


async def test_protocol_pipelined_commands_reject_control_characters(
    connect_protocol: ConnectProtocol,
) -> None:
    async def server_callback(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 testserver\r\n")
        await writer.drain()
        writer.close()

    protocol = await connect_protocol(server_callback)
    await protocol.read_response(timeout=1.0)

    with pytest.raises(ValueError):
        await protocol.execute_pipelined_commands([b"NOOP\r\nRSET"], timeout=1.0)


async def test_protocol_pipelined_commands_not_connected() -> None:
    protocol = SMTPProtocol()

    with pytest.raises(SMTPServerDisconnected):
        await protocol.execute_pipelined_commands([b"NOOP"], timeout=1.0)
