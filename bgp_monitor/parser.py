"""Parsers for BGP update streams (JSONL), the RPKI ROA table (JSON) and the
AS-relationship fixture (JSON)."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ASRelationships, ROA, Update


def parse_updates(path: str | Path) -> list[Update]:
    """Read a JSONL file of BGP updates.

    Each line is a JSON object:
      {"type": "announce", "prefix": "203.0.113.0/24", "origin_as": 64500,
       "as_path": [64496, 64500], "peer_as": 64496, "timestamp": "..."}
      {"type": "withdraw", "prefix": "203.0.113.0/24", "peer_as": 64496}
    """
    updates: list[Update] = []
    for line_no, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        msg_type = obj.get("type")
        if msg_type not in ("announce", "withdraw"):
            raise ValueError(f"{path}:{line_no}: unknown update type {msg_type!r}")
        as_path = tuple(int(a) for a in obj.get("as_path", []))
        origin = obj.get("origin_as")
        if msg_type == "announce":
            if origin is None and as_path:
                origin = as_path[-1]
            if origin is None:
                raise ValueError(f"{path}:{line_no}: announcement without origin AS")
        updates.append(
            Update(
                msg_type=msg_type,
                prefix=obj["prefix"],
                origin_as=int(origin) if origin is not None else None,
                as_path=as_path,
                peer_as=int(obj["peer_as"]) if obj.get("peer_as") is not None else None,
                timestamp=obj.get("timestamp", ""),
            )
        )
    return updates


def parse_roas(path: str | Path) -> list[ROA]:
    """Read the ROA table: {"roas": [{"prefix": ..., "origin_as": ..., "max_length": ...}]}"""
    data = json.loads(Path(path).read_text())
    return [
        ROA(prefix=r["prefix"], origin_as=int(r["origin_as"]), max_length=int(r["max_length"]))
        for r in data.get("roas", [])
    ]


def parse_relationships(path: str | Path) -> ASRelationships:
    """Read AS relationships: {"64496": {"providers": [], "peers": [64501], "customers": [64500]}}"""
    data = json.loads(Path(path).read_text())
    rels: dict[int, dict[str, list[int]]] = {}
    for asn_str, rel in data.items():
        rels[int(asn_str)] = {
            "providers": [int(x) for x in rel.get("providers", [])],
            "peers": [int(x) for x in rel.get("peers", [])],
            "customers": [int(x) for x in rel.get("customers", [])],
        }
    return ASRelationships(relationships=rels)
