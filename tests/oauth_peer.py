"""
An in-process SMTP peer for exercising real client <-> server SMTP dialogs
without binding a network socket (sandboxed CI forbids listening sockets).

A pair of in-memory transports connects a scripted server-side protocol
directly to the client's :class:`SMTPProtocol`, so all client code paths -
framing, timeouts, cancellation, SASL exchanges - run unchanged.
"""

import asyncio
import base64
import json
from typing import Any

from aiosmtplib.protocol import SMTPProtocol
from aiosmtplib.smtp import SMTP


class InMemoryTransport(asyncio.Transport):
    """
    A transport that delivers every write to the peer protocol on the next
    event loop iteration, emulating a connected stream socket.
    """

    def __init__(
        self, loop: asyncio.AbstractEventLoop, peer: asyncio.Protocol
    ) -> None:
        self._loop = loop
        self._peer = peer
        self._closing = False
        self._closed = False

    def write(self, data: bytes) -> None:
        if not self._closed:
            self._loop.call_soon(self._peer.data_received, bytes(data))

    def can_write_eof(self) -> bool:
        return True

    def write_eof(self) -> None:
        self.close()

    def is_closing(self) -> bool:
        return self._closing

    def close(self) -> None:
        if self._closed:
            return
        self._closing = True
        self._loop.call_soon(self._do_close)

    def abort(self) -> None:
        self.close()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        # The test connection is plaintext.
        if name == "sslcontext":
            return None
        if name == "peername":
            return ("memory-peer", 0)
        return default

    def _do_close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._peer.connection_lost(None)


# A scripted per-attempt outcome: ``(xoauth2_status, final_smtp_code)``,
# e.g. ``("401", "535")`` for an expired token.
ChallengeOutcome = tuple[str, str]
Outcome = str | ChallengeOutcome


class XOAUTH2Peer(asyncio.Protocol):
    """
    Scripted SMTP peer advertising XOAUTH2.

    ``outcomes`` is consumed one entry per ``AUTH XOAUTH2`` attempt:

    * ``"235"`` - authentication succeeds.
    * ``("401", "535")`` - a base64-encoded JSON ``334`` error challenge is
      sent, the peer waits for the empty line that terminates the SASL
      exchange, and then replies with the given final code.
    * ``"535"`` - a bare ``535`` failure reply with no preceding challenge.
    * ``"451"`` / ``"421"`` - a transient service failure reply (no
      challenge); the connection is closed for ``"421"`` as a real server
      would.
    * ``"gibberish"`` - a non-numeric, protocol-level garbage reply.
    * ``"disconnect"`` - the transport is closed mid-exchange.

    When ``response_gate`` is set, AUTH replies wait on the event, which lets
    a test deterministically cancel while a response is in flight.
    """

    def __init__(self, outcomes: list[Outcome]) -> None:
        self.outcomes = outcomes
        # When set, AUTH responses wait on this event before being sent, so a
        # test can deterministically cancel while a reply is in flight.
        self.response_gate: asyncio.Event | None = None
        # Set as soon as an AUTH XOAUTH2 command line arrives.
        self.auth_received: asyncio.Event = asyncio.Event()
        self.transport: InMemoryTransport | None = None
        self.commands: list[bytes] = []
        self.tokens: list[str] = []
        self.empty_challenge_responses = 0
        self.auth_attempts = 0
        self._buffer = b""
        self._pending_final: str | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self._send(b"220 memory-peer ESMTP\r\n")

    def data_received(self, data: bytes) -> None:
        self._buffer += data
        while b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            self._handle_line(line)

    def _handle_line(self, line: bytes) -> None:
        if line == b"":
            self.empty_challenge_responses += 1
            if self._pending_final is not None:
                final_code = self._pending_final
                self._pending_final = None
                self._send(f"{final_code} 5.7.8 authentication failed\r\n".encode())
            return

        self.commands.append(line)
        if line.startswith(b"EHLO"):
            self._send(b"250-memory-peer\r\n250 AUTH XOAUTH2 PLAIN LOGIN\r\n")
        elif line.startswith(b"QUIT"):
            self._send(b"221 2.0.0 Bye\r\n")
        elif line.startswith(b"AUTH XOAUTH2"):
            self.auth_attempts += 1
            self.auth_received.set()
            self._handle_xoauth2(line)

    def _handle_xoauth2(self, line: bytes) -> None:
        try:
            payload = line.split(b" ", 2)[2]
            decoded = base64.b64decode(payload)
            token = decoded.split(b"auth=Bearer ")[1].split(b"\x01")[0]
            self.tokens.append(token.decode("utf-8", errors="replace"))
        except (IndexError, ValueError):
            self.tokens.append("<unparseable>")

        outcome = self.outcomes.pop(0)
        self._respond(outcome)

    def _respond(self, outcome: Outcome) -> None:
        if self.response_gate is not None:
            asyncio.ensure_future(self._respond_when_open(outcome))
            return
        self._respond_now(outcome)

    async def _respond_when_open(self, outcome: Outcome) -> None:
        assert self.response_gate is not None
        await self.response_gate.wait()
        self._respond_now(outcome)

    def _respond_now(self, outcome: Outcome) -> None:
        if outcome == "235":
            self._send(b"235 2.7.0 Accepted\r\n")
        elif outcome in ("421", "451"):
            self._send(f"{outcome} 4.7.0 temporary failure\r\n".encode())
            if outcome == "421" and self.transport is not None:
                self.transport.close()
        elif outcome == "gibberish":
            self._send(b"not-an-smtp-reply\r\n")
        elif outcome == "disconnect":
            if self.transport is not None:
                self.transport.close()
        elif outcome == "535":
            self._send(b"535 5.7.8 bare authentication failure\r\n")
        else:
            status, final_code = outcome
            challenge = base64.b64encode(json.dumps({"status": status}).encode())
            self._send(b"334 " + challenge + b"\r\n")
            self._pending_final = final_code

    def _send(self, data: bytes) -> None:
        if self.transport is not None:
            self.transport.write(data)


class FakeTokenProvider:
    """
    A scripted async OAuth token provider.

    Entries are returned in order; an exception instance is raised instead.
    Every call and handed-out token is recorded so tests can assert fetch
    counts and verify that secrets never reach logs or exceptions.
    """

    def __init__(self, tokens: list[Any]) -> None:
        self._tokens = list(tokens)
        self.calls = 0
        self.returned: list[str] = []

    async def __call__(self) -> str:
        self.calls += 1
        token = self._tokens.pop(0)
        if isinstance(token, BaseException):
            raise token
        self.returned.append(token)
        return token


async def connect_smtp_with_peer(
    client: SMTP, peer: XOAUTH2Peer
) -> SMTPProtocol:
    """
    Wire ``client`` to ``peer`` over in-memory transports and consume the
    server greeting. The client is left connected but not authenticated.
    """
    loop = asyncio.get_running_loop()
    client.loop = loop
    client._connect_lock = asyncio.Lock()
    await client._connect_lock.acquire()

    client_protocol = SMTPProtocol(
        loop=loop, connection_lost_callback=client._on_connection_lost
    )
    client_transport = InMemoryTransport(loop, peer)
    peer_transport = InMemoryTransport(loop, client_protocol)

    peer.connection_made(peer_transport)
    client_protocol.connection_made(client_transport)

    client.protocol = client_protocol
    client.transport = client_transport

    await client_protocol.read_response()
    return client_protocol
