"""
Model evaluation on the labelled CERT sessions (read-only: baselines are NOT updated).

Reports both views, because they answer different questions:
* session level – of all sessions, how many flags are real? (precision / recall / ROC-AUC)
* user level    – was each malicious user flagged at least once? and how many
                  benign users were flagged at least once? (the original project
                  quoted only malicious-user recall, which looks much better)
"""
from __future__ import annotations

from typing import Dict, Optional

import numpy as np
import pandas as pd

from core.config import AppConfig, get_config
from ml.baselines import BaselineStore
from ml.behavior_model import BehaviorModel
from ml.datasets import add_insider_labels, load_sessions, row_to_session
from ml.features import behavior_features, rule_score


def score_frame(df: pd.DataFrame, store: BaselineStore, model: BehaviorModel, cfg: AppConfig) -> pd.DataFrame:
    s = cfg.ml.behavior
    feature_rows, rule_scores = [], []
    for row in df.itertuples(index=False):
        session = row_to_session(row)
        b = store.get(session["user_id"]) or store.get_or_create(session["user_id"])
        feature_rows.append(behavior_features(session, b))
        rule_scores.append(rule_score(session, s.rule_weights))
    out = df.copy()
    out["if_score"] = model.if_scores(feature_rows) if feature_rows else []
    out["rule_score"] = rule_scores
    out["hybrid_score"] = s.if_weight * out["if_score"] + s.rules_weight * out["rule_score"]
    return out


def metrics(y: np.ndarray, score: np.ndarray, users: pd.Series, threshold: float) -> Dict[str, float]:
    from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score

    pred = score >= threshold
    frame = pd.DataFrame({"user": users.values, "y": y, "pred": pred})
    per_user = frame.groupby("user").agg(mal=("y", "max"), flagged=("pred", "max"))
    mal = per_user[per_user.mal == 1]
    ben = per_user[per_user.mal == 0]
    return {
        "roc_auc": round(float(roc_auc_score(y, score)), 4),
        "average_precision": round(float(average_precision_score(y, score)), 4),
        "threshold": threshold,
        "flag_rate": round(float(pred.mean()), 4),
        "session_precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "session_recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "malicious_users_flagged": f"{int(mal.flagged.sum())}/{len(mal)}",
        "benign_users_flagged": f"{int(ben.flagged.sum())}/{len(ben)}",
    }


def evaluate(cfg: Optional[AppConfig] = None, limit: Optional[int] = None) -> dict:
    cfg = cfg or get_config()
    df = load_sessions(cfg.path(cfg.data.replay_dataset_path))
    df = add_insider_labels(df, cfg.path(cfg.data.insiders_path))
    if limit:
        df = df.sample(n=min(limit, len(df)), random_state=0)
    # read-only copy of the seed baselines so evaluation never mutates runtime state
    import tempfile
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp()) / "baselines.sqlite"
    store = BaselineStore(tmp, seed_path=cfg.path(cfg.ml.behavior.baselines_seed_path))
    scored = score_frame(df, store, BehaviorModel(cfg), cfg)
    y = scored["insider"].to_numpy()
    thr = cfg.ml.behavior.anomaly_threshold
    return {
        "sessions": int(len(scored)),
        "insider_sessions": int(y.sum()),
        "isolation_forest": metrics(y, scored["if_score"].to_numpy(), scored["user_id"], thr),
        "rules_only": metrics(y, scored["rule_score"].to_numpy(), scored["user_id"], thr),
        "hybrid": metrics(y, scored["hybrid_score"].to_numpy(), scored["user_id"], thr),
        "config": {"if_weight": cfg.ml.behavior.if_weight, "rules_weight": cfg.ml.behavior.rules_weight},
    }
