"""
Tabular Q-learning for the Response Agent — deliberately small and explainable.

The decision problem
--------------------
For each security incident the agent chooses ONE response action. That choice
does not change which incident arrives next, so every incident is a one-step
episode (a "contextual bandit"). We therefore use the standard Q-learning
update with a terminal next state, i.e. discount factor γ = 0 by default:

    Q(s, a) ← Q(s, a) + α · (r + γ · max_a' Q(s', a') − Q(s, a))
                                  └─ 0 for terminal transitions ─┘

1. STATE   (s)  – discretised view of the risk assessment (see ``encode_state``)
2. ACTION  (a)  – ALLOW | MONITOR | ESCALATE | BLOCK
3. REWARD  (r)  – from ground truth (simulations / labelled replay) or the
                  analyst's APPROVE / DENY on the dashboard (see ``reward_*``)
4. Q-TABLE      – dict state → {action: value}, stored as JSON (not pickle)
5. POLICY       – greedy at inference, ε-greedy while training; unseen states
                  fall back to a rule-based mapping (clearly reported)
6. UPDATE       – ``QLearningAgent.update`` (the formula above)
"""
from __future__ import annotations

import json
import logging
import random
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional

logger = logging.getLogger("soc.ml.rl")

# ── 2. ACTIONS ──────────────────────────────────────────────────────────────
ACTIONS: List[str] = ["ALLOW", "MONITOR", "ESCALATE", "BLOCK"]
ACTION_SEVERITY = {a: i for i, a in enumerate(ACTIONS)}  # ordering used by guardrails

# Rule-based policy used for states the agent has never seen (and as a baseline).
RULE_POLICY = {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "ESCALATE"}


# ── 1. STATE ────────────────────────────────────────────────────────────────
def encode_state(risk_level: str, risk_score: float, signal_count: int, cold_start: bool) -> str:
    """Discretise a risk assessment into a short, human-readable state key.

    risk_level   LOW / MEDIUM / HIGH
    score bucket 0..4  (risk score split into 5 equal-width bins)
    signals      0 = none, 1 = 1–2, 2 = 3–4, 3 = 5+ triggered rules
    baseline     cold (new user, little history) / warm

    e.g. "HIGH|s4|r2|warm" = high risk, score ≥ 0.8, 3–4 rules, established baseline
    """
    bucket = min(int(max(risk_score, 0.0) * 5), 4)
    sig = 0 if signal_count <= 0 else 1 if signal_count <= 2 else 2 if signal_count <= 4 else 3
    return f"{risk_level}|s{bucket}|r{sig}|{'cold' if cold_start else 'warm'}"


# ── 3. REWARD ───────────────────────────────────────────────────────────────
# Ground-truth reward: did the action fit what really happened?
REWARD_MALICIOUS = {"BLOCK": 1.0, "ESCALATE": 0.8, "MONITOR": -0.4, "ALLOW": -1.0}
REWARD_BENIGN = {"ALLOW": 1.0, "MONITOR": 0.5, "ESCALATE": -0.3, "BLOCK": -1.0}


def reward_from_ground_truth(action: str, malicious: bool) -> float:
    return (REWARD_MALICIOUS if malicious else REWARD_BENIGN)[action]


def reward_from_analyst(approved: bool) -> float:
    """Analyst approved the recommended action → +1, denied it → −1."""
    return 1.0 if approved else -1.0


# ── 4. Q-TABLE  +  5. POLICY  +  6. UPDATE ──────────────────────────────────
@dataclass
class Recommendation:
    action: str
    q_values: Dict[str, float]
    state: str
    source: str  # "q_table" | "rule_fallback" | "exploration"
    visits: int

    def to_dict(self) -> dict:
        return {"action": self.action, "state": self.state, "source": self.source, "visits": self.visits,
                "q_values": {a: round(v, 4) for a, v in self.q_values.items()}}


class QLearningAgent:
    def __init__(self, path: Path, alpha: float = 0.1, gamma: float = 0.0, epsilon: float = 0.1,
                 seed: Optional[int] = None, seed_path: Optional[Path] = None):
        """``path`` is where the table is loaded from and saved to.

        ``seed_path`` (optional) is a pre-trained table that is read ONLY when ``path`` does not
        exist yet. The platform uses it so analyst feedback is saved to data/runtime/ and the
        committed models/rl/q_table.json is never modified at runtime.
        """
        self.path = Path(path)
        self.seed_path = Path(seed_path) if seed_path else None
        self.alpha, self.gamma, self.epsilon = alpha, gamma, epsilon
        self.q: Dict[str, Dict[str, float]] = {}
        self.visits: Dict[str, int] = {}
        self.updates = 0
        self.metadata: Dict[str, object] = {}
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self.load()

    # Q-table ----------------------------------------------------------------
    def q_values(self, state: str) -> Dict[str, float]:
        return self.q.setdefault(state, {a: 0.0 for a in ACTIONS})

    # Policy -----------------------------------------------------------------
    def recommend(self, state: str, risk_level: str, explore: bool = False) -> Recommendation:
        visits = self.visits.get(state, 0)
        if explore and self._rng.random() < self.epsilon:
            action = self._rng.choice(ACTIONS)
            return Recommendation(action, dict(self.q_values(state)), state, "exploration", visits)
        if visits == 0:
            return Recommendation(RULE_POLICY.get(risk_level, "MONITOR"), {a: 0.0 for a in ACTIONS},
                                  state, "rule_fallback", 0)
        qv = self.q[state]
        best = max(ACTIONS, key=lambda a: (qv[a], -ACTION_SEVERITY[a]))  # tie → milder action
        return Recommendation(best, dict(qv), state, "q_table", visits)

    # Update -----------------------------------------------------------------
    def update(self, state: str, action: str, reward: float, next_state: Optional[str] = None) -> float:
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action}")
        with self._lock:
            qv = self.q_values(state)
            future = 0.0 if next_state is None else max(self.q_values(next_state).values())
            td_target = reward + self.gamma * future
            qv[action] += self.alpha * (td_target - qv[action])
            self.visits[state] = self.visits.get(state, 0) + 1
            self.updates += 1
            return qv[action]

    # Persistence (JSON — safe to load, readable in a text editor) -----------
    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format": "q_table/v1",
            "actions": ACTIONS,
            "hyperparameters": {"alpha": self.alpha, "gamma": self.gamma, "epsilon": self.epsilon},
            "updates": self.updates,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "metadata": self.metadata,
            "visits": self.visits,
            "q_table": {s: {a: round(v, 6) for a, v in qv.items()} for s, qv in sorted(self.q.items())},
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=1))
        tmp.replace(self.path)

    def load(self) -> None:
        source = self.path
        if not source.exists() and self.seed_path is not None and self.seed_path.exists():
            source = self.seed_path  # first run: start from the pre-trained policy
        if not source.exists():
            logger.info("No Q-table found — starting empty (rule fallback until trained)",
                        extra={"path": str(self.path)})
            return
        try:
            data = json.loads(source.read_text())
            self.q = {s: {a: float(qv.get(a, 0.0)) for a in ACTIONS} for s, qv in data.get("q_table", {}).items()}
            self.visits = {s: int(v) for s, v in data.get("visits", {}).items()}
            self.updates = int(data.get("updates", 0))
            self.metadata = dict(data.get("metadata", {}))
        except Exception as exc:
            logger.error("Q-table could not be loaded — starting empty", extra={"error": str(exc)})
            self.q, self.visits, self.updates = {}, {}, 0

    def stats(self) -> dict:
        greedy = {s: max(ACTIONS, key=lambda a: qv[a]) for s, qv in self.q.items() if self.visits.get(s)}
        dist: Dict[str, int] = {a: 0 for a in ACTIONS}
        for a in greedy.values():
            dist[a] += 1
        return {
            "states": len(self.q), "trained_states": len(greedy), "updates": self.updates,
            "hyperparameters": {"alpha": self.alpha, "gamma": self.gamma, "epsilon": self.epsilon},
            "greedy_action_distribution": dist, "metadata": self.metadata, "path": str(self.path),
            "seed_path": str(self.seed_path) if self.seed_path else None,
        }

    def table(self, limit: int = 200) -> List[dict]:
        rows = []
        for s, qv in sorted(self.q.items(), key=lambda kv: -self.visits.get(kv[0], 0))[:limit]:
            rows.append({"state": s, "visits": self.visits.get(s, 0), "best_action": max(ACTIONS, key=lambda a: qv[a]),
                         "q_values": {a: round(v, 4) for a, v in qv.items()}})
        return rows


def apply_guardrails(action: str, risk_level: str, min_action: Mapping[str, str],
                     max_action: Mapping[str, str]) -> tuple[str, Optional[str]]:
    """Clamp the learned action into the policy band for the risk level."""
    floor = min_action.get(risk_level)
    ceil = max_action.get(risk_level)
    if floor and ACTION_SEVERITY[action] < ACTION_SEVERITY[floor]:
        return floor, f"raised from {action} to policy minimum {floor} for {risk_level} risk"
    if ceil and ACTION_SEVERITY[action] > ACTION_SEVERITY[ceil]:
        return ceil, f"lowered from {action} to policy maximum {ceil} for {risk_level} risk"
    return action, None
