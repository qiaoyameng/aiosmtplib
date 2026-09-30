"""
Immutable snapshots of server ESMTP capabilities.
"""

import dataclasses
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import Literal, TypeAlias


__all__ = (
    "CapabilitiesObserver",
    "CapabilityPhase",
    "CapabilitySnapshot",
    "ExtensionSelector",
)

CapabilityPhase: TypeAlias = Literal["cleartext", "tls"]


@dataclasses.dataclass(frozen=True)
class CapabilitySnapshot:
    """
    An immutable view of the capabilities negotiated with the server for one
    connection generation and negotiation phase.

    A new snapshot is published after each successful EHLO command. Snapshots
    are invalidated (replaced by ``None``) as soon as the capabilities they
    describe no longer apply: on STARTTLS upgrade, on connection loss, and on
    reconnect.
    """

    generation: int
    """
    Connection generation this snapshot belongs to. Incremented on every
    connect, so a reconnect always produces a new generation.
    """

    phase: CapabilityPhase
    """
    The negotiation phase the capabilities were obtained in: ``"cleartext"``
    or ``"tls"``.
    """

    extensions: Mapping[str, str]
    """
    ESMTP extensions supported by the server, as an immutable mapping.
    """

    auth_methods: tuple[str, ...]
    """
    Authentication methods advertised by the server.
    """

    supports_esmtp: bool
    """
    Whether the server responded to EHLO (vs. falling back to HELO).
    """

    def __post_init__(self) -> None:
        object.__setattr__(self, "extensions", MappingProxyType(dict(self.extensions)))
        object.__setattr__(self, "auth_methods", tuple(self.auth_methods))

    def supports_extension(self, extension: str, /) -> bool:
        """
        Tests if the server supports the ESMTP service extension given.
        """
        return extension.lower() in self.extensions


CapabilitiesObserver: TypeAlias = Callable[[CapabilitySnapshot | None], None]
"""
Callback invoked with the new snapshot when capabilities are published, or
with ``None`` when the current capabilities are invalidated.
"""

ExtensionSelector: TypeAlias = Callable[[CapabilitySnapshot | None], Iterable[str]]
"""
Callback invoked before each MAIL command with the current snapshot (or
``None``), returning extra MAIL options to send.
"""
