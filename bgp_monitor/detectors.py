"""Anomaly detectors: prefix hijack, more-specific announcements and
route leaks (valley-free path violations, RFC 7908 style)."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ASRelationships, ROA, Update
from .rpki import RPKIResult, validate


@dataclass
class Finding:
    kind: str  # "HIJACK" | "TOO_SPECIFIC" | "LEAK"
    detail: str


def detect_origin_mismatch(update: Update, roas: list[ROA]) -> Finding | None:
    """The origin AS is not the AS authorised by the covering ROA — the
    classic signature of a prefix hijack (or mis-origination)."""
    result = validate(update, roas)
    if result.origin_mismatch:
        return Finding("HIJACK", result.reason)
    return None


def detect_too_specific(update: Update, roas: list[ROA]) -> Finding | None:
    """The origin is authorised but announces a more-specific prefix than
    its ROA maxLength permits."""
    result = validate(update, roas)
    if result.too_specific:
        return Finding("TOO_SPECIFIC", result.reason)
    return None


def detect_route_leak(update: Update, relationships: ASRelationships) -> Finding | None:
    """Valley-free violation: in propagation order a legitimate path is
    zero or more "up" steps, at most one "peer" step, then zero or more
    "down" steps. An "up" or "peer" step after a "down" step means an AS
    propagated routes learned from one provider/peer onward to another —
    a route leak."""
    path = update.propagation_path()
    if len(path) < 3:
        return None  # need at least origin -> middle -> neighbour to leak
    steps = [relationships.relation(a, b) for a, b in zip(path, path[1:])]
    phase = 0  # 0 = going up, 1 = peer step taken, 2 = going down
    for i, step in enumerate(steps):
        if step == "unknown":
            continue
        if step == "up":
            if phase == 2:
                return Finding(
                    "LEAK",
                    f"valley-free violation: 'up' step AS{path[i]}->AS{path[i + 1]} "
                    f"after a 'down' step in path {' -> '.join('AS' + str(a) for a in path)}",
                )
            if phase == 1:
                return Finding(
                    "LEAK",
                    f"valley-free violation: 'up' step AS{path[i]}->AS{path[i + 1]} "
                    f"after the peer step in path {' -> '.join('AS' + str(a) for a in path)}",
                )
        elif step == "peer":
            if phase == 1:
                return Finding(
                    "LEAK",
                    f"valley-free violation: second peer step AS{path[i]}->AS{path[i + 1]} "
                    f"in path {' -> '.join('AS' + str(a) for a in path)}",
                )
            if phase == 2:
                return Finding(
                    "LEAK",
                    f"valley-free violation: 'peer' step AS{path[i]}->AS{path[i + 1]} "
                    f"after a 'down' step in path {' -> '.join('AS' + str(a) for a in path)}",
                )
            phase = 1
        elif step == "down":
            phase = 2
    return None


def run_detectors(
    update: Update, roas: list[ROA], relationships: ASRelationships
) -> tuple[RPKIResult, list[Finding]]:
    """Run every detector over one announcement."""
    rpki_result = validate(update, roas)
    findings: list[Finding] = []
    for detector in (detect_origin_mismatch, detect_too_specific):
        finding = detector(update, roas)
        if finding:
            findings.append(finding)
    leak = detect_route_leak(update, relationships)
    if leak:
        findings.append(leak)
    return rpki_result, findings
