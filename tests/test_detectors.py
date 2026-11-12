"""Detector and end-to-end pipeline tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bgp_monitor.analyze import analyze_stream, analyze_update
from bgp_monitor.detectors import (
    detect_origin_mismatch,
    detect_route_leak,
    detect_too_specific,
)
from bgp_monitor.mitigate import generate_filters
from bgp_monitor.models import ASRelationships, Update
from bgp_monitor.parser import parse_relationships, parse_roas, parse_updates

BASE = Path(__file__).resolve().parents[1]
ROAS = parse_roas(BASE / "sample_data" / "roas.json")
RELS = parse_relationships(BASE / "sample_data" / "as_relationships.json")


def announce(prefix, origin, path):
    return Update(
        msg_type="announce", prefix=prefix, origin_as=origin,
        as_path=tuple(path), peer_as=path[0],
    )


def test_hijack_detector_flags_wrong_origin():
    f = detect_origin_mismatch(announce("203.0.113.0/24", 64600, [64496, 64501, 64600]), ROAS)
    assert f is not None and f.kind == "HIJACK", f


def test_hijack_detector_quiet_for_legit_origin():
    f = detect_origin_mismatch(announce("203.0.113.0/24", 64500, [64496, 64500]), ROAS)
    assert f is None, f


def test_too_specific_detector():
    f = detect_too_specific(announce("192.0.2.128/25", 64500, [64496, 64500]), ROAS)
    assert f is not None and f.kind == "TOO_SPECIFIC", f
    assert detect_too_specific(announce("192.0.2.0/24", 64500, [64496, 64500]), ROAS) is None


def test_leak_detector_catches_valley_free_violation():
    # 64502 learns 64503's prefix from provider 64501 and leaks it to provider 64496:
    # propagation 64503 -> 64501 (up) -> 64502 (down) -> 64496 (up) = valley.
    f = detect_route_leak(announce("198.51.100.0/24", 64503, [64496, 64502, 64501, 64503]), RELS)
    assert f is not None and f.kind == "LEAK", f


def test_leak_detector_accepts_normal_paths():
    assert detect_route_leak(announce("203.0.113.0/24", 64500, [64496, 64500]), RELS) is None
    assert detect_route_leak(announce("198.51.100.0/24", 64503, [64496, 64501, 64503]), RELS) is None


def test_sample_stream_catches_all_planted_anomalies():
    updates = parse_updates(BASE / "sample_data" / "updates.jsonl")
    analyses = analyze_stream(updates, ROAS, RELS)
    verdicts = [a.verdict for a in analyses]
    assert verdicts.count("HIJACK SUSPECT") == 2, verdicts
    assert verdicts.count("LEAK SUSPECT") == 1, verdicts
    assert verdicts.count("RPKI INVALID") == 1, verdicts
    assert verdicts.count("VALID") == 4, verdicts
    assert verdicts.count("WITHDRAW") == 1, verdicts


def test_mitigation_filters_cover_anomalies():
    updates = parse_updates(BASE / "sample_data" / "updates.jsonl")
    cfg = generate_filters(analyze_stream(updates, ROAS, RELS))
    assert "deny 203.0.113.0/24 le 32" in cfg, cfg
    assert "deny 192.0.2.128/25 le 32" in cfg, cfg
    assert "deny 198.51.100.0/24 le 32" in cfg, cfg
    assert "permit 0.0.0.0/0 le 32" in cfg, cfg


def test_verdict_precedence_hijack_over_specific():
    # Wrong origin AND more specific: must surface as hijack.
    a = analyze_update(announce("203.0.113.128/25", 64600, [64496, 64501, 64600]), ROAS, RELS)
    assert a.verdict == "HIJACK SUSPECT", a
