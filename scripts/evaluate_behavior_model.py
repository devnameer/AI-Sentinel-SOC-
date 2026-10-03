#!/usr/bin/env python
"""
Evaluate the insider-threat behaviour model on the labelled CERT r4.2 sessions.

Compares three scoring modes (Isolation Forest only, rules only, hybrid) at the
configured threshold. Read-only: runtime baselines are not modified.

Usage (repository root):
    python scripts/evaluate_behavior_model.py
    python scripts/evaluate_behavior_model.py --json reports/behavior_eval.json --limit 20000
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from ml.evaluation import evaluate  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="evaluate on a random sample of N sessions")
    ap.add_argument("--json", type=Path, default=None, help="also write the report as JSON")
    args = ap.parse_args()

    report = evaluate(limit=args.limit)
    print(f"Sessions: {report['sessions']:,}   insider-window sessions: {report['insider_sessions']}")
    cols = ["roc_auc", "average_precision", "flag_rate", "session_precision", "session_recall",
            "malicious_users_flagged", "benign_users_flagged"]
    print(f"\n{'mode':<18}" + "".join(f"{c:>24}" for c in cols))
    for mode in ("isolation_forest", "rules_only", "hybrid"):
        m = report[mode]
        print(f"{mode:<18}" + "".join(f"{str(m[c]):>24}" for c in cols))
    print(f"\nthreshold = {report['hybrid']['threshold']}, hybrid weights = {report['config']}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2))
        print(f"Report written to {args.json}")


if __name__ == "__main__":
    main()
