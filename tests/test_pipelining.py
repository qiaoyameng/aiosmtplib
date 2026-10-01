"""
PIPELINING (RFC 2920) tests, using a controllable raw SMTP server.
"""

import asyncio
import socket
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any

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


class PipeliningServer:
    """
    A raw SMTP server that only replies to envelope commands (MAIL/RCPT)
    once a whole batch of ``batch_size`` commands has arrived.

    A client that waits for each reply before sending the next command
    deadlocks against this server (with ``batch_size`` > 1), so a successful
    send proves the envelope commands were pipelined, i.e. in flight
    concurrently.
    """

    def __init__(
        self,
        *,
        batch_size: int = 1,
        advertise_pipelining: bool = True,
        refused_recipients: set[str] | None = None,
        refuse_mail: bool = False,
        reply_delay: float = 0.0,
        close_on_batch: bool = False,
        malformed_batch_reply: bool = False,
    ) -> None:
        self.batch_size = batch_size
        self.advertise_pipelining = advertise_pipelining
        self.refused_recipients = refused_recipients or set()
        self.refuse_mail = refuse_mail
        self.reply_delay = reply_delay
        self.close_on_batch = close_on_batch
        self.malformed_batch_reply = malformed_batch_reply

        self.server: asyncio.AbstractServer | None = None
        self.received_commands: list[str] = []
        # Number of envelope commands received before each batch of replies,
        # i.e. how many commands were in flight concurrently.
        self.batch_sizes_in_flight: list[int] = []
        self.data_command_received = False
        self.message_data: bytes | None = None

    @property
    def port(self) -> int:
        assert self.server is not None
        return int(self.server.sockets[0].getsockname()[1])

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"220 pipelining.test ESMTP\r\n")
        await writer.drain()
        pending: list[bytes] = []
        data_lines: list[bytes] | None = None
        while True:
            try:
                line = await reader.readline()
            except ConnectionResetError:
                break
            if not line:
                break
            line = line.rstrip(b"\r\n")
            if data_lines is not None:
                if line == b".":
                    self.message_data = b"\r\n".join(data_lines)
                    data_lines = None
                    writer.write(b"250 2.0.0 Message accepted\r\n")
                    await writer.drain()
                else:
                    data_lines.append(line)
                continue
            command = line.partition(b" ")[0].upper()
            self.received_commands.append(line.decode("ascii"))
            if command == b"EHLO":
                pipelining_line = (
                    b"250-PIPELINING\r\n" if self.advertise_pipelining else b""
                )
                writer.write(
                    b"250-pipelining.test greets you\r\n"
                    + pipelining_line
                    + b"250 HELP\r\n"
                )
                await writer.drain()
            elif command in (b"MAIL", b"RCPT"):
                pending.append(line)
                if len(pending) >= self.batch_size:
                    await self._reply_to_envelope(pending, writer)
                    pending = []
            elif command == b"DATA":
                self.data_command_received = True
                data_lines = []
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                await writer.drain()
            elif command in (b"RSET", b"NOOP"):
                writer.write(b"250 2.0.0 OK\r\n")
                await writer.drain()
            elif command == b"QUIT":
                writer.write(b"221 2.0.0 Bye\r\n")
                await writer.drain()
                break
        writer.close()

    async def _reply_to_envelope(
        self, pending: list[bytes], writer: asyncio.StreamWriter
    ) -> None:
        if self.reply_delay:
            await asyncio.sleep(self.reply_delay)
        if self.close_on_batch:
            writer.close()
            return
        self.batch_sizes_in_flight.append(len(pending))
        try:
            if self.malformed_batch_reply:
                writer.write(b"garbage without a status code\r\n")
            else:
                for command_line in pending:
                    writer.write(self._envelope_reply(command_line))
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            # The client may have hung up (e.g. after a cancellation).
            pass

    def _envelope_reply(self, command_line: bytes) -> bytes:
        if command_line.upper().startswith(b"MAIL"):
            if self.refuse_mail:
                return b"550 5.7.1 Sender refused\r\n"
            return b"250 2.1.0 Sender OK\r\n"
        address = command_line.split(b":", 1)[1].strip().strip(b"<>").decode("ascii")
        if address in self.refused_recipients:
            return f"550 5.1.1 No such user: {address}\r\n".encode("ascii")
        return b"250 2.1.5 Recipient OK\r\n"


PipeliningServerFactory = Callable[..., Awaitable[PipeliningServer]]


@pytest_asyncio.fixture
async def pipelining_server_factory(
    bind_address: str,
) -> AsyncGenerator[PipeliningServerFactory]:
    servers: list[asyncio.AbstractServer] = []

    async def factory(**kwargs: Any) -> PipeliningServer:
        test_server = PipeliningServer(**kwargs)
        test_server.server = await asyncio.start_server(
            test_server.handle_client, host=bind_address, port=0, family=socket.AF_INET
        )
        servers.append(test_server.server)
        return test_server

    yield factory

    for server in servers:
        server.close()


async def test_sendmail_pipelines_envelope_commands(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(batch_size=3)
    recipients = ["one@example.com", "two@example.com"]
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    async with client:
        errors, response = await client.sendmail(sender_str, recipients, message_str)

    assert errors == {}
    assert response != ""
    # MAIL and both RCPTs were all in flight before any envelope reply; a
    # sequential client would deadlock waiting for the MAIL reply.
    assert server.batch_sizes_in_flight == [3]
    assert server.received_commands[1:4] == [
        f"MAIL FROM:<{sender_str}>",
        "RCPT TO:<one@example.com>",
        "RCPT TO:<two@example.com>",
    ]
    assert server.data_command_received
    assert server.message_data is not None
    assert "Hello World" in server.message_data.decode("ascii")


async def test_sendmail_pipelining_partial_recipient_refusal(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(
        batch_size=5, refused_recipients={"two@example.com", "four@example.com"}
    )
    recipients = [
        "one@example.com",
        "two@example.com",
        "three@example.com",
        "four@example.com",
    ]
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    async with client:
        errors, response = await client.sendmail(sender_str, recipients, message_str)

    # Responses are paired to commands in order, so each refusal is
    # attributed to the correct address.
    assert set(errors) == {"two@example.com", "four@example.com"}
    assert errors["two@example.com"].code == SMTPStatus.mailbox_does_not_exist
    assert "two@example.com" in errors["two@example.com"].message
    assert errors["four@example.com"].code == SMTPStatus.mailbox_does_not_exist
    assert "four@example.com" in errors["four@example.com"].message
    # The message is still delivered to the remaining recipients.
    assert response != ""
    assert server.data_command_received
    assert server.message_data is not None


async def test_sendmail_pipelining_mail_refused_skips_data(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(batch_size=3, refuse_mail=True)
    recipients = ["one@example.com", "two@example.com"]
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    await client.connect()
    with pytest.raises(SMTPSenderRefused) as exc_info:
        await client.sendmail(sender_str, recipients, message_str)

    assert exc_info.value.sender == sender_str
    assert not server.data_command_received

    # Every pipelined response was collected, so the connection is still in
    # sync (sendmail's RSET and this NOOP get their own replies).
    assert client.is_connected
    response = await client.noop()
    assert response.code == SMTPStatus.completed
    await client.quit()


async def test_sendmail_pipelining_all_recipients_refused(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    refused = {"one@example.com", "two@example.com"}
    server = await pipelining_server_factory(batch_size=3, refused_recipients=refused)
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    await client.connect()
    with pytest.raises(SMTPRecipientsRefused) as exc_info:
        await client.sendmail(sender_str, sorted(refused), message_str)

    assert {error.recipient for error in exc_info.value.recipients} == refused
    assert not server.data_command_received

    assert client.is_connected
    response = await client.noop()
    assert response.code == SMTPStatus.completed
    await client.quit()


async def test_sendmail_pipelining_cancelled_closes_connection(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    # The server holds its replies, so the batch responses are still in
    # flight when the send is cancelled.
    server = await pipelining_server_factory(batch_size=2, reply_delay=10.0)
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    await client.connect()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            client.sendmail(sender_str, ["one@example.com"], message_str),
            timeout=0.2,
        )

    # The late replies must not be left to pair with the next mail's
    # commands, so the connection is dropped.
    assert not client.is_connected
    with pytest.raises(SMTPServerDisconnected):
        await client.noop()


async def test_sendmail_pipelining_disconnect_closes_connection(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(batch_size=2, close_on_batch=True)
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    await client.connect()
    with pytest.raises(SMTPServerDisconnected):
        await client.sendmail(sender_str, ["one@example.com"], message_str)

    assert not client.is_connected


async def test_sendmail_pipelining_malformed_response_closes_connection(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(batch_size=2, malformed_batch_reply=True)
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    await client.connect()
    with pytest.raises(SMTPResponseException):
        await client.sendmail(sender_str, ["one@example.com"], message_str)

    assert not client.is_connected


async def test_sendmail_without_pipelining_advertised_sends_sequentially(
    pipelining_server_factory: PipeliningServerFactory,
    hostname: str,
    sender_str: str,
    message_str: str,
) -> None:
    server = await pipelining_server_factory(batch_size=1, advertise_pipelining=False)
    client = SMTP(hostname=hostname, port=server.port, timeout=5.0)

    async with client:
        errors, response = await client.sendmail(
            sender_str, ["one@example.com", "two@example.com"], message_str
        )

    assert errors == {}
    assert response != ""
    # Each command was replied to before the next one arrived.
    assert server.batch_sizes_in_flight == [1, 1, 1]
    assert server.data_command_received


async def test_protocol_pipelined_commands_pair_coalesced_responses(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        data = await reader.readuntil(b"RCPT TO:<b@example.com>\r\n")
        assert data == b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.com>\r\n"
        # Both replies in a single write, so the second is parsed from the
        # buffer left over by the first.
        writer.write(b"250 2.1.0 Sender OK\r\n550 5.1.1 No such user\r\n")
        await writer.drain()

    protocol = await connect_protocol(client_connected)
    responses = await protocol.execute_pipelined_commands(
        [b"MAIL FROM:<a@example.com>", b"RCPT TO:<b@example.com>"], timeout=1.0
    )

    assert [(response.code, response.message) for response in responses] == [
        (250, "2.1.0 Sender OK"),
        (550, "5.1.1 No such user"),
    ]


async def test_protocol_pipelined_commands_split_response(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"SECOND\r\n")
        # The second reply is split across writes.
        writer.write(b"250 first\r\n250 sec")
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(b"ond\r\n")
        await writer.drain()

    protocol = await connect_protocol(client_connected)
    responses = await protocol.execute_pipelined_commands(
        [b"FIRST", b"SECOND"], timeout=1.0
    )

    assert [response.message for response in responses] == ["first", "second"]


async def test_protocol_pipelined_commands_malformed_response_closes(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"SECOND\r\n")
        writer.write(b"250 first\r\ngarbage!!!\r\n")
        await writer.drain()

    protocol = await connect_protocol(client_connected)
    with pytest.raises(SMTPResponseException):
        await protocol.execute_pipelined_commands([b"FIRST", b"SECOND"], timeout=1.0)

    assert not protocol.is_connected


async def test_protocol_pipelined_commands_disconnect(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"SECOND\r\n")
        # Only one reply for two commands, then a disconnect.
        writer.write(b"250 first\r\n")
        await writer.drain()
        writer.close()

    protocol = await connect_protocol(client_connected)
    with pytest.raises(SMTPServerDisconnected):
        await protocol.execute_pipelined_commands([b"FIRST", b"SECOND"], timeout=1.0)

    assert not protocol.is_connected


async def test_protocol_pipelined_commands_cancel_closes(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"SECOND\r\n")
        await asyncio.sleep(10)

    protocol = await connect_protocol(client_connected)
    task = asyncio.create_task(
        protocol.execute_pipelined_commands([b"FIRST", b"SECOND"], timeout=10.0)
    )
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert not protocol.is_connected


async def test_protocol_pipelined_commands_requires_commands(
    connect_protocol: ConnectProtocol,
) -> None:
    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.read(1000)

    protocol = await connect_protocol(client_connected)
    with pytest.raises(ValueError, match="No commands provided"):
        await protocol.execute_pipelined_commands([])


@pytest.mark.parametrize("command", [b"NOOP\n", b"NOOP\x1f"])
async def test_protocol_pipelined_commands_rejects_injected_commands(
    command: bytes,
) -> None:
    protocol = SMTPProtocol()
    with pytest.raises(ValueError, match="prohibited control character"):
        await protocol.execute_pipelined_commands([command])


async def test_protocol_pipelined_commands_not_connected() -> None:
    protocol = SMTPProtocol()
    with pytest.raises(SMTPServerDisconnected):
        await protocol.execute_pipelined_commands([b"NOOP"])
