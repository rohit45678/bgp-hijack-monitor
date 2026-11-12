"""RPKI validation tests (plain asserts; also pytest-compatible)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bgp_monitor.models import ROA, Update
from bgp_monitor.rpki import RPKIState, validate

ROAS = [
    ROA(prefix="203.0.113.0/24", origin_as=64500, max_length=24),
    ROA(prefix="192.0.2.0/24", origin_as=64500, max_length=24),
]


def announce(prefix, origin, path):
    return Update(msg_type="announce", prefix=prefix, origin_as=origin, as_path=tuple(path))


def test_valid_exact_prefix():
    r = validate(announce("203.0.113.0/24", 64500, [64496, 64500]), ROAS)
    assert r.state is RPKIState.VALID, r


def test_valid_more_specific_within_maxlength():
    roas = [ROA(prefix="10.0.0.0/8", origin_as=64500, max_length=24)]
    r = validate(announce("10.1.2.0/24", 64500, [64496, 64500]), roas)
    assert r.state is RPKIState.VALID, r


def test_origin_mismatch_is_invalid():
    r = validate(announce("203.0.113.0/24", 64600, [64496, 64600]), ROAS)
    assert r.state is RPKIState.INVALID and r.origin_mismatch, r


def test_too_specific_is_invalid():
    r = validate(announce("192.0.2.128/25", 64500, [64496, 64500]), ROAS)
    assert r.state is RPKIState.INVALID and r.too_specific, r


def test_not_found_when_no_roa():
    r = validate(announce("192.0.3.0/24", 64502, [64496, 64502]), ROAS)
    assert r.state is RPKIState.NOTFOUND, r
