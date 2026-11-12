# BGP Hijack & Route-Leak Monitor
Autonomous monitor that watches global BGP updates for prefix hijacks and route leaks, validates announcements against RPKI/IRR data, and injects filters to mitigate malicious or accidental mis-originations.
**Tech stack:** Python, BGP, RPKI, IRR, Route Security
**Highlights:** real-time BGP update analysis; RPKI origin validation; automated filter injection; alerting on anomalous announcements.

## What it does

Given a stream of BGP update messages, the monitor validates every announcement
against a table of RPKI Route Origin Authorizations (ROAs), runs anomaly
detectors over it, prints a per-update verdict, and auto-generates prefix-list
filters that would drop the bad announcements at the border.

| Verdict | Meaning |
|---|---|
| `VALID` | Origin authorised by ROA (or no ROA exists and path is sane) |
| `HIJACK SUSPECT` | Origin AS is not the AS authorised by the covering ROA |
| `RPKI INVALID` | Right origin, but the announcement is more specific than the ROA `maxLength` |
| `LEAK SUSPECT` | Valley-free path violation — an AS propagated a route learned from one provider/peer to another (RFC 7908 style) |
| `WITHDRAW` | Withdrawal message (no verdict applied) |

## Features

- **BGP update parser** — JSONL update stream (announcements + withdrawals).
- **RPKI origin validation** — RFC 6811-style `VALID / INVALID / NOTFOUND`
  classification, distinguishing origin mismatch from maxLength violations.
- **Hijack detector** — flags announcements whose origin AS is not ROA-authorised.
- **More-specific detector** — flags announcements longer than the ROA `maxLength`.
- **Route-leak detector** — walks the AS path in propagation order using a
  provider/peer/customer relationship fixture and flags valley-free violations
  (an `up` or `peer` step after a `down` step, or a second peer step).
- **Automated mitigation** — emits an IOS-style `ip prefix-list` config denying
  every anomalous announcement, ready to paste into a border ingress policy.
- **Offline fixtures** — sample update stream with planted anomalies (2 hijacks,
  1 route leak, 1 more-specific), a 3-entry ROA table, and a 6-AS relationship
  topology, so the whole pipeline runs with no live BGP feed.

## Architecture

```
sample_data/updates.jsonl ──► parser ──► Update objects
sample_data/roas.json ────────────────► RPKI validator ──┐
sample_data/as_relationships.json ────► leak detector ───┤
                                                         ▼
                              detectors ──► analyze ──► verdicts
                                                         │
                                                         ▼
                                          mitigate ──► prefix-list config
```

```
bgp_monitor/
  models.py       Update / ROA / ASRelationships data types
  parser.py       JSONL updates, ROA table, relationship fixture parsers
  rpki.py         RFC 6811-style origin validation
  detectors.py    hijack, more-specific and valley-free leak detectors
  analyze.py      per-update pipeline and verdict precedence
  mitigate.py     prefix-list filter generation
main.py           CLI entry point
sample_data/      updates.jsonl, roas.json, as_relationships.json
tests/            plain-assert test suite (pytest-compatible) + run_tests.py
```

## How to run

```bash
python3 main.py --updates sample_data/updates.jsonl
python3 tests/run_tests.py        # 16 tests
```

Custom inputs: `--roas <file>`, `--relationships <file>`,
`--filters-out <file>` (default `mitigation_filters.txt`).

## Sample output

```
Loaded 9 updates, 3 ROAs

Per-update verdicts:
  203.0.113.0/24     origin AS64500  path [AS64496 AS64500]  ->  VALID  (RPKI VALID: origin AS64500 authorised, /24 within maxLength)
  198.51.100.0/24    origin AS64503  path [AS64496 AS64501 AS64503]  ->  VALID  (...)
  192.0.2.0/24       origin AS64500  path [AS64496 AS64500]  ->  VALID  (...)
  203.0.113.0/24     origin AS64600  path [AS64496 AS64501 AS64600]  ->  HIJACK SUSPECT  (origin AS64600 not authorised by ROA (expects AS64500))
  192.0.2.128/25     origin AS64500  path [AS64496 AS64500]  ->  RPKI INVALID  (announced /25 is more specific than ROA maxLength /24 for AS64500)
  198.51.100.0/24    origin AS64503  path [AS64496 AS64502 AS64501 AS64503]  ->  LEAK SUSPECT  (valley-free violation: 'up' step AS64502->AS64496 after a 'down' step ...)
  203.0.113.128/25   origin AS64600  path [AS64496 AS64501 AS64600]  ->  HIJACK SUSPECT  (...)
  192.0.3.0/24       origin AS64502  path [AS64496 AS64502]  ->  VALID  (RPKI NOTFOUND: no ROA covers this prefix)
  192.0.3.0/24       via AS64496  ->  WITHDRAW (no verdict)

Summary:
  VALID          4
  HIJACK SUSPECT 2
  LEAK SUSPECT   1
  RPKI INVALID   1
  WITHDRAW       1

Mitigation: 4 anomalous announcement(s); filters written to mitigation_filters.txt
```

Generated mitigation config (excerpt):

```
! HIJACK SUSPECT: origin AS64600 not authorised by ROA (expects AS64500)
! prefix 203.0.113.0/24 announced by origin AS64600 via peer AS64496
ip prefix-list PL-BGP-MITIGATION seq 10 deny 203.0.113.0/24 le 32
...
ip prefix-list PL-BGP-MITIGATION seq 50 permit 0.0.0.0/0 le 32
```

## Input formats

**Update** (one JSON object per line):
```json
{"type": "announce", "prefix": "203.0.113.0/24", "origin_as": 64500,
 "as_path": [64496, 64500], "peer_as": 64496, "timestamp": "2026-11-12T09:00:01Z"}
```

**ROA table**: `{"roas": [{"prefix": "203.0.113.0/24", "origin_as": 64500, "max_length": 24}]}`

**AS relationships**: `{"64501": {"providers": [], "peers": [64496], "customers": [64502, 64503]}}`
