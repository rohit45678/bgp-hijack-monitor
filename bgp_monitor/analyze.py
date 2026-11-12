"""Analysis pipeline: one update -> RPKI result + detector findings -> verdict.

Verdict precedence:
  1. Origin mismatch            -> HIJACK SUSPECT
  2. Route leak                 -> LEAK SUSPECT
  3. More-specific than ROA     -> RPKI INVALID
  4. Otherwise                  -> VALID
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import Finding, run_detectors
from .models import ASRelationships, ROA, Update
from .rpki import RPKIResult


@dataclass
class Analysis:
    update: Update
    verdict: str  # VALID | HIJACK SUSPECT | LEAK SUSPECT | RPKI INVALID | WITHDRAW
    rpki: RPKIResult | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def summary_line(self) -> str:
        upd = self.update
        if upd.msg_type == "withdraw":
            return f"{upd.prefix:<18} via AS{upd.peer_as}  ->  WITHDRAW (no verdict)"
        path = " ".join(f"AS{a}" for a in upd.as_path)
        details = "; ".join(f.detail for f in self.findings)
        if not details and self.rpki is not None:
            details = f"RPKI {self.rpki.state.value}: {self.rpki.reason}"
        return (
            f"{upd.prefix:<18} origin AS{upd.origin_as:<6} path [{path}]  "
            f"->  {self.verdict}  ({details})"
        )


def analyze_update(update: Update, roas: list[ROA], relationships: ASRelationships) -> Analysis:
    if update.msg_type == "withdraw":
        return Analysis(update=update, verdict="WITHDRAW")
    rpki_result, findings = run_detectors(update, roas, relationships)
    kinds = {f.kind for f in findings}
    if "HIJACK" in kinds:
        verdict = "HIJACK SUSPECT"
    elif "LEAK" in kinds:
        verdict = "LEAK SUSPECT"
    elif "TOO_SPECIFIC" in kinds:
        verdict = "RPKI INVALID"
    else:
        verdict = "VALID"
    return Analysis(update=update, verdict=verdict, rpki=rpki_result, findings=findings)


def analyze_stream(
    updates: list[Update], roas: list[ROA], relationships: ASRelationships
) -> list[Analysis]:
    return [analyze_update(u, roas, relationships) for u in updates]
