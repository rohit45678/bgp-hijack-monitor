"""Parser tests."""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bgp_monitor.parser import parse_relationships, parse_roas, parse_updates

BASE = Path(__file__).resolve().parents[1]


def test_parse_sample_updates():
    updates = parse_updates(BASE / "sample_data" / "updates.jsonl")
    assert len(updates) == 9, len(updates)
    assert updates[0].msg_type == "announce"
    assert updates[0].origin_as == 64500
    assert updates[0].propagation_path() == (64500, 64496)
    assert updates[-1].msg_type == "withdraw"


def test_parse_roas_and_relationships():
    roas = parse_roas(BASE / "sample_data" / "roas.json")
    assert len(roas) == 3
    rels = parse_relationships(BASE / "sample_data" / "as_relationships.json")
    assert rels.relation(64500, 64496) == "up"
    assert rels.relation(64501, 64496) == "peer"
    assert rels.relation(64501, 64502) == "down"
    assert rels.relation(64500, 64503) == "unknown"


def test_parser_rejects_bad_json():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        fh.write('{"type": "announce", "prefix": "10.0.0.0/8", "origin_as": 64500}\n')
        fh.write("not json\n")
        name = fh.name
    try:
        parse_updates(name)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for malformed JSONL")
