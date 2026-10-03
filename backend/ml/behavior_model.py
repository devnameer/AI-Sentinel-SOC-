"""
Insider-threat behaviour model — inference only (training lives in scripts/).

Pipeline for one session:
    session + user baseline ─► 18 features ─► Isolation Forest score (0–1)
                            └► rule signals ─► rule score (0–1)
    final score = IF score                              (scoring_mode: isolation_forest)
                = if_weight·IF + rules_weight·rules     (scoring_mode: hybrid, default)

Models are loaded once, lazily, and a missing/corrupt file never crashes the
API: ``status()`` reports what is wrong and scoring raises ModelUnavailable.

Security note: .joblib files are pickles. Only load model files you created
or downloaded from a source you trust.
"""
from __future__ import annotations

import json
import logging
import threading
import warnings
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

from core.config import AppConfig, get_config
from ml.baselines import UserBaseline
from ml.features import behavior_features, dimension_scores, rule_score, triggered_rules

logger = logging.getLogger("soc.ml.behavior")


class ModelUnavailable(RuntimeError):
    pass


@dataclass
class BehaviorScore:
    score: float
    if_score: float
    rule_score: float
    flagged: bool
    threshold: float
    scoring_mode: str
    verdict: str
    dimension_scores: Dict[str, float]
    triggered_rules: List[str]
    features: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 4), "if_score": round(self.if_score, 4),
            "rule_score": round(self.rule_score, 4), "flagged": self.flagged, "threshold": self.threshold,
            "scoring_mode": self.scoring_mode, "verdict": self.verdict,
            "dimension_scores": self.dimension_scores, "triggered_rules": self.triggered_rules,
            "features": {k: round(v, 4) for k, v in self.features.items()},
        }


def verdict_for(score: float, threshold: float) -> str:
    if score >= 0.8:
        return "CRITICAL"
    if score >= 0.6:
        return "HIGH"
    if score >= threshold:
        return "MEDIUM"
    return "LOW"


class BehaviorModel:
    def __init__(self, cfg: Optional[AppConfig] = None):
        self.cfg = cfg or get_config()
        self._lock = threading.Lock()
        self._model = None
        self._columns: List[str] = []
        self._bounds: Dict[str, float] = {}
        self._error: Optional[str] = None
        self._warnings: List[str] = []

    def _load(self) -> None:
        if self._model is not None or self._error is not None:
            return
        with self._lock:
            if self._model is not None or self._error is not None:
                return
            s = self.cfg.ml.behavior
            try:
                import joblib

                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    model = joblib.load(self.cfg.path(s.model_path))
                self._warnings = sorted({str(w.message).split(" when using")[0] + " (retrain to silence)"
                                         for w in caught if "InconsistentVersion" in type(w.message).__name__})
                columns = json.loads(self.cfg.path(s.feature_columns_path).read_text())
                bounds = json.loads(self.cfg.path(s.score_bounds_path).read_text())
                if getattr(model, "n_features_in_", len(columns)) != len(columns):
                    raise ValueError("feature column count does not match the model")
                self._model, self._columns, self._bounds = model, columns, bounds
                logger.info("Behaviour model loaded", extra={"features": len(columns)})
            except FileNotFoundError as exc:
                self._error = f"Model file missing: {exc.filename}. Run scripts/train_behavior_model.py"
            except Exception as exc:  # corrupt pickle, version mismatch, bad JSON…
                self._error = f"Could not load behaviour model: {type(exc).__name__}: {exc}"
            if self._error:
                logger.error(self._error)

    def status(self) -> dict:
        self._load()
        s = self.cfg.ml.behavior
        return {
            "name": "behavior_isolation_forest",
            "status": "loaded" if self._model is not None else "unavailable",
            "error": self._error,
            "warnings": self._warnings,
            "path": s.model_path,
            "features": len(self._columns),
            "scoring_mode": s.scoring_mode,
            "threshold": s.anomaly_threshold,
            "estimators": getattr(self._model, "n_estimators", None),
        }

    def if_scores(self, rows: List[Dict[str, float]]) -> np.ndarray:
        """Vectorised Isolation Forest scores in [0, 1] (1 = most anomalous)."""
        self._load()
        if self._model is None:
            raise ModelUnavailable(self._error or "behaviour model unavailable")
        x = np.array([[r.get(c, 0.0) for c in self._columns] for r in rows], dtype=float)
        x = np.nan_to_num(x, nan=0.0, posinf=100.0, neginf=-100.0)
        raw = self._model.score_samples(x)
        lo, hi = self._bounds["raw_min"], self._bounds["raw_max"]
        return np.clip(1.0 - (raw - lo) / (hi - lo), 0.0, 1.0)

    def if_score(self, features: Dict[str, float]) -> float:
        return float(self.if_scores([features])[0])

    def score(self, session: dict, baseline: UserBaseline) -> BehaviorScore:
        s = self.cfg.ml.behavior
        feats = behavior_features(session, baseline)
        if_s = self.if_score(feats)
        dims = dimension_scores(session, baseline)
        rules = triggered_rules(session, dims)
        r_s = rule_score(session, s.rule_weights)
        if s.scoring_mode == "hybrid":
            final = s.if_weight * if_s + s.rules_weight * r_s
        else:
            final = if_s
        final = float(np.clip(final, 0.0, 1.0))
        return BehaviorScore(
            score=final, if_score=if_s, rule_score=r_s, flagged=final >= s.anomaly_threshold,
            threshold=s.anomaly_threshold, scoring_mode=s.scoring_mode,
            verdict=verdict_for(final, s.anomaly_threshold), dimension_scores=dims,
            triggered_rules=rules, features=feats,
        )


_instance: Optional[BehaviorModel] = None


def get_behavior_model() -> BehaviorModel:
    global _instance
    if _instance is None:
        _instance = BehaviorModel()
    return _instance


def reset_behavior_model() -> None:
    global _instance
    _instance = None
