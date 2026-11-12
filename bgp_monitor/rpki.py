"""RPKI origin validation (RFC 6483 / RFC 6811 style).

An announcement is:
  VALID    - a covering ROA authorises the origin AS and the announced
             prefix length does not exceed the ROA maxLength.
  INVALID  - a covering ROA exists but either the origin AS is not
             authorised (origin mismatch) or the announcement is more
             specific than the ROA maxLength allows.
  NOTFOUND - no ROA covers the announced prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .models import ROA, Update


class RPKIState(Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOTFOUND = "NOTFOUND"


@dataclass
class RPKIResult:
    state: RPKIState
    reason: str
    origin_mismatch: bool = False
    too_specific: bool = False
    covering_roas: list[ROA] | None = None


def validate(update: Update, roas: list[ROA]) -> RPKIResult:
    covering = [r for r in roas if r.covers(update)]
    if not covering:
        return RPKIResult(
            state=RPKIState.NOTFOUND,
            reason="no ROA covers this prefix",
            covering_roas=[],
        )

    authorised = [r for r in covering if r.origin_as == update.origin_as]
    if not authorised:
        expected = ", ".join(f"AS{r.origin_as}" for r in covering)
        return RPKIResult(
            state=RPKIState.INVALID,
            reason=f"origin AS{update.origin_as} not authorised by ROA (expects {expected})",
            origin_mismatch=True,
            covering_roas=covering,
        )

    if any(update.prefixlen <= r.max_length for r in authorised):
        return RPKIResult(
            state=RPKIState.VALID,
            reason=f"origin AS{update.origin_as} authorised, /{update.prefixlen} within maxLength",
            covering_roas=covering,
        )

    max_len = max(r.max_length for r in authorised)
    return RPKIResult(
        state=RPKIState.INVALID,
        reason=(
            f"announced /{update.prefixlen} is more specific than ROA maxLength "
            f"/{max_len} for AS{update.origin_as}"
        ),
        too_specific=True,
        covering_roas=covering,
    )
