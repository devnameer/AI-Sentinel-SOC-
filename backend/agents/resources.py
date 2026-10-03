"""
Process-wide shared resources (loaded lazily, once).

Keeping them here means models are loaded on first use — not on every request,
and never trained at API start-up.
"""
from __future__ import annotations

import threading
from typing import Optional

from core.config import get_config
from ml.baselines import BaselineStore
from ml.q_learning import QLearningAgent

_lock = threading.Lock()
_store: Optional[BaselineStore] = None
_q_agent: Optional[QLearningAgent] = None


def get_baseline_store() -> BaselineStore:
    global _store
    if _store is None:
        with _lock:
            if _store is None:
                cfg = get_config()
                _store = BaselineStore(cfg.path(cfg.ml.behavior.baselines_path),
                                       seed_path=cfg.path(cfg.ml.behavior.baselines_seed_path))
    return _store


def get_q_agent() -> QLearningAgent:
    global _q_agent
    if _q_agent is None:
        with _lock:
            if _q_agent is None:
                cfg = get_config()
                # Live learning (analyst feedback) is saved to the runtime copy; the pre-trained
                # table in models/rl/ is only the starting point and is never overwritten here.
                _q_agent = QLearningAgent(cfg.path(cfg.rl.runtime_q_table_path), alpha=cfg.rl.learning_rate,
                                          gamma=cfg.rl.discount_factor, epsilon=cfg.rl.epsilon,
                                          seed_path=cfg.path(cfg.rl.q_table_path))
    return _q_agent


def reset_resources() -> None:
    """Tests / demo reset."""
    global _store, _q_agent
    with _lock:
        _store, _q_agent = None, None
