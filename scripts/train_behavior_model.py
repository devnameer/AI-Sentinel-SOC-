#!/usr/bin/env python
"""
Re-train the insider-threat Isolation Forest with YOUR installed scikit-learn.

Why: the shipped model was trained with scikit-learn 1.6.1; newer versions load
it with a warning. Re-training removes the warning and makes the model fully
reproducible from this repository.

Method (no label leakage into training):
  * time split — sessions before --split-date are used for training,
    sessions after it for evaluation;
  * sessions inside a known insider window are removed from training
    (Isolation Forest is unsupervised: it should learn "normal");
  * features are the same 18 features used at inference (ml/features.py),
    computed against the seed baselines.

Outputs go to --out-dir (default models/behavior_retrained/) so the shipped model
is never overwritten by accident. Point ml.behavior.* paths in config.yaml at the
new files to use them.

Usage (repository root):
    python scripts/train_behavior_model.py
    python scripts/train_behavior_model.py --estimators 300 --contamination 0.05
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from core.config import get_config  # noqa: E402
from ml.baselines import BaselineStore  # noqa: E402
from ml.datasets import add_insider_labels, load_sessions, row_to_session  # noqa: E402
from ml.features import behavior_features  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--split-date", default="2010-12-01")
    ap.add_argument("--estimators", type=int, default=200)
    ap.add_argument("--contamination", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", type=Path, default=ROOT / "models" / "behavior_retrained")
    args = ap.parse_args()

    import joblib
    import sklearn
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score

    cfg = get_config()
    df = add_insider_labels(load_sessions(cfg.path(cfg.data.replay_dataset_path)), cfg.path(cfg.data.insiders_path))
    store = BaselineStore(Path(tempfile.mkdtemp()) / "b.sqlite", seed_path=cfg.path(cfg.ml.behavior.baselines_seed_path))
    columns = json.loads(cfg.path(cfg.ml.behavior.feature_columns_path).read_text())

    def matrix(frame):
        rows = []
        for row in frame.itertuples(index=False):
            s = row_to_session(row)
            b = store.get(s["user_id"]) or store.get_or_create(s["user_id"])
            f = behavior_features(s, b)
            rows.append([f[c] for c in columns])
        return np.nan_to_num(np.asarray(rows, dtype=float), nan=0.0, posinf=100.0, neginf=-100.0)

    train = df[(df.session_start < args.split_date) & (df.insider == 0)]
    test = df[df.session_start >= args.split_date]
    print(f"train: {len(train):,} benign sessions   test: {len(test):,} sessions ({int(test.insider.sum())} insider)")
    x_train, x_test = matrix(train), matrix(test)

    model = IsolationForest(n_estimators=args.estimators, contamination=args.contamination,
                            random_state=args.seed, n_jobs=-1).fit(x_train)
    raw_train = model.score_samples(x_train)
    bounds = {"raw_min": float(np.percentile(raw_train, 0.5)), "raw_max": float(np.percentile(raw_train, 99.5))}
    raw = model.score_samples(x_test)
    score = np.clip(1.0 - (raw - bounds["raw_min"]) / (bounds["raw_max"] - bounds["raw_min"]), 0, 1)
    y = test.insider.to_numpy()
    if y.sum():
        print(f"held-out ROC-AUC {roc_auc_score(y, score):.4f}   average precision {average_precision_score(y, score):.4f}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.out_dir / "isolation_forest.joblib")
    (args.out_dir / "feature_columns.json").write_text(json.dumps(columns, indent=2))
    (args.out_dir / "score_bounds.json").write_text(json.dumps(bounds, indent=2))
    (args.out_dir / "training_info.json").write_text(json.dumps({
        "sklearn_version": sklearn.__version__, "split_date": args.split_date, "train_sessions": len(train),
        "estimators": args.estimators, "contamination": args.contamination, "seed": args.seed}, indent=2))
    print(f"Saved model to {args.out_dir} — update ml.behavior paths in backend/config/config.yaml to use it.")


if __name__ == "__main__":
    main()
