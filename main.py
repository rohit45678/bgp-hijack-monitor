#!/usr/bin/env python3
"""BGP hijack & route-leak monitor -- CLI.

Usage:
    python main.py --updates sample_data/updates.jsonl
    python main.py --updates sample_data/updates.jsonl \
        --roas sample_data/roas.json \
        --relationships sample_data/as_relationships.json \
        --filters-out mitigation_filters.txt
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bgp_monitor.analyze import analyze_stream
from bgp_monitor.mitigate import generate_filters
from bgp_monitor.parser import parse_relationships, parse_roas, parse_updates

BASE = Path(__file__).resolve().parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="BGP hijack & route-leak monitor")
    ap.add_argument("--updates", required=True, help="JSONL file of BGP updates")
    ap.add_argument("--roas", default=str(BASE / "sample_data" / "roas.json"))
    ap.add_argument(
        "--relationships", default=str(BASE / "sample_data" / "as_relationships.json")
    )
    ap.add_argument(
        "--filters-out",
        default="mitigation_filters.txt",
        help="where to write generated mitigation filters (default: mitigation_filters.txt)",
    )
    args = ap.parse_args(argv)

    updates = parse_updates(args.updates)
    roas = parse_roas(args.roas)
    relationships = parse_relationships(args.relationships)

    print(f"Loaded {len(updates)} updates, {len(roas)} ROAs\n")
    print("Per-update verdicts:")
    analyses = analyze_stream(updates, roas, relationships)
    for a in analyses:
        print("  " + a.summary_line)

    counts = Counter(a.verdict for a in analyses)
    print("\nSummary:")
    for verdict in ("VALID", "HIJACK SUSPECT", "LEAK SUSPECT", "RPKI INVALID", "WITHDRAW"):
        if counts.get(verdict):
            print(f"  {verdict:<14} {counts[verdict]}")

    filters = generate_filters(analyses)
    out = Path(args.filters_out)
    out.write_text(filters)
    anomalies = sum(counts.get(v, 0) for v in ("HIJACK SUSPECT", "LEAK SUSPECT", "RPKI INVALID"))
    print(f"\nMitigation: {anomalies} anomalous announcement(s); filters written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
