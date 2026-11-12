"""Core data types for the BGP monitor."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Update:
    """One BGP update message (announcement or withdrawal)."""

    msg_type: str  # "announce" or "withdraw"
    prefix: str
    origin_as: int | None = None
    as_path: tuple[int, ...] = ()  # neighbour-first order, origin last (standard AS_PATH)
    peer_as: int | None = None
    timestamp: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.prefix)

    @property
    def prefixlen(self) -> int:
        return self.network.prefixlen

    def propagation_path(self) -> tuple[int, ...]:
        """AS path in traffic-propagation order: origin first, neighbour last."""
        return tuple(reversed(self.as_path))


@dataclass(frozen=True)
class ROA:
    """One RPKI Route Origin Authorization record."""

    prefix: str
    origin_as: int
    max_length: int

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.prefix)

    def covers(self, update: Update) -> bool:
        """True if this ROA's prefix is a supernet of (or equal to) the update's."""
        net = self.network
        upd = update.network
        return upd.subnet_of(net)


@dataclass
class ASRelationships:
    """Provider / peer / customer relationships keyed by ASN.

    relationships[asn] = {"providers": [...], "peers": [...], "customers": [...]}
    """

    relationships: dict[int, dict[str, list[int]]] = field(default_factory=dict)

    def relation(self, a: int, b: int) -> str:
        """How traffic flowing A -> B is classified.

        Returns "up" (customer -> provider), "peer", "down" (provider ->
        customer), or "unknown" if the fixture has no record of the pair.
        """
        rel = self.relationships.get(a, {})
        if b in rel.get("providers", []):
            return "up"
        if b in rel.get("peers", []):
            return "peer"
        if b in rel.get("customers", []):
            return "down"
        return "unknown"
