"""
Per-user behavioural baselines (what "normal" looks like for each user).

* Seeded from the CERT r4.2 training period (1,001 users) — the seed file is
  read-only; a working copy lives in data/runtime/ so the demo can be reset.
* Users the platform has never seen (e.g. the account running the host
  collectors) get a cold-start baseline built from population averages,
  marked ``cold_start=True`` (lower confidence). The original project instead
  mapped unknown users to a *random* CERT user — that is removed.
* Score-gated learning: only sessions scored below the update threshold may
  change the learned habits, so an attacker cannot slowly "teach" the
  baseline that exfiltration is normal.
"""
from __future__ import annotations

import json
import logging
import math
import shutil
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Mapping, Optional

import numpy as np

logger = logging.getLogger("soc.ml.baselines")


@dataclass
class UserBaseline:
    user_id: str
    last_updated: str
    observation_days: int
    cold_start: bool
    login_hour_mean: float
    login_hour_std: float
    login_hours_observed: List[float]
    known_devices: List[str]
    daily_file_access_mean: float
    daily_file_access_std: float
    daily_volume_history: List[float]
    typical_max_sensitivity: int
    role_sensitivity_ceiling: int
    daily_email_mean: float
    daily_email_std: float
    department: str
    feature_history: List[dict] = field(default_factory=list)
    recent_scores: List[float] = field(default_factory=list)
    dept_file_access_mean: float = 0.0
    dept_file_access_std: float = 1.0
    dept_email_mean: float = 0.0
    dept_email_std: float = 1.0
    dept_login_hour_mean: float = 9.0
    dept_login_hour_std: float = 2.0
    dept_usb_rate: float = 0.0

    def summary(self) -> dict:
        """Compact view for prompts and the UI (no long history lists)."""
        return {
            "user_id": self.user_id,
            "department": self.department,
            "observation_days": self.observation_days,
            "cold_start": self.cold_start,
            "login_hour_mean": round(self.login_hour_mean, 2),
            "login_hour_std": round(self.login_hour_std, 2),
            "known_devices": self.known_devices[:10],
            "daily_file_access_mean": round(self.daily_file_access_mean, 2),
            "daily_email_mean": round(self.daily_email_mean, 2),
            "typical_max_sensitivity": self.typical_max_sensitivity,
            "role_sensitivity_ceiling": self.role_sensitivity_ceiling,
            "dept_usb_rate": round(self.dept_usb_rate, 3),
            "recent_scores": [round(s, 3) for s in self.recent_scores],
        }


def circular_mean(hours: List[float]) -> float:
    if not hours:
        return 9.0
    angles = [h * 2 * math.pi / 24 for h in hours]
    mean = math.atan2(float(np.mean(np.sin(angles))), float(np.mean(np.cos(angles))))
    result = (mean * 24 / (2 * math.pi)) % 24
    return float(result if result < 24.0 else 0.0)


def circular_std(hours: List[float]) -> float:
    if len(hours) < 2:
        return 4.0
    angles = [h * 2 * math.pi / 24 for h in hours]
    r = min(math.sqrt(float(np.mean(np.sin(angles))) ** 2 + float(np.mean(np.cos(angles))) ** 2), 0.9999)
    return float(math.sqrt(-2 * math.log(r)) * 24 / (2 * math.pi))


class BaselineStore:
    """Thread-safe SQLite-backed baseline store with an in-memory cache."""

    def __init__(self, path: Path, seed_path: Optional[Path] = None):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._cache: Dict[str, UserBaseline] = {}
        self._population: Optional[dict] = None
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if seed_path and Path(seed_path).exists():
                shutil.copyfile(seed_path, self.path)
                logger.info("Baselines initialised from seed", extra={"seed": str(seed_path)})
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS baselines (user_id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        self._load_all()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=10)

    def _load_all(self) -> None:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT user_id, data FROM baselines").fetchall()
            known = set(UserBaseline.__dataclass_fields__)
            self._cache = {}
            for user_id, data in rows:
                payload = {k: v for k, v in json.loads(data).items() if k in known}
                self._cache[user_id] = UserBaseline(**payload)
        logger.info("Baselines loaded", extra={"users": len(self._cache)})

    def __len__(self) -> int:
        return len(self._cache)

    def users(self) -> List[str]:
        return sorted(self._cache)

    def get(self, user_id: str) -> Optional[UserBaseline]:
        return self._cache.get(user_id)

    def save(self, b: UserBaseline) -> None:
        with self._lock:
            self._cache[b.user_id] = b
            with self._connect() as conn:
                conn.execute("INSERT OR REPLACE INTO baselines (user_id, data) VALUES (?, ?)",
                             (b.user_id, json.dumps(asdict(b))))

    # ── cold start ────────────────────────────────────────────────────────
    def population_stats(self) -> dict:
        if self._population is None:
            items = list(self._cache.values())
            if not items:
                self._population = {"file_mean": 1.0, "file_std": 1.0, "email_mean": 3.0, "email_std": 3.0,
                                    "hour_mean": 9.0, "usb_rate": 0.2}
            else:
                self._population = {
                    "file_mean": float(np.mean([b.daily_file_access_mean for b in items])),
                    "file_std": float(max(np.mean([b.daily_file_access_std for b in items]), 1.0)),
                    "email_mean": float(np.mean([b.daily_email_mean for b in items])),
                    "email_std": float(max(np.mean([b.daily_email_std for b in items]), 1.0)),
                    "hour_mean": float(circular_mean([b.login_hour_mean for b in items])),
                    "usb_rate": float(np.mean([b.dept_usb_rate for b in items])),
                }
        return self._population

    def get_or_create(self, user_id: str, department: str = "unassigned") -> UserBaseline:
        """Return the user's baseline, creating a cold-start one if unknown."""
        b = self.get(user_id)
        if b is not None:
            return b
        p = self.population_stats()
        b = UserBaseline(
            user_id=user_id, last_updated=str(date.today()), observation_days=0, cold_start=True,
            login_hour_mean=p["hour_mean"], login_hour_std=4.0, login_hours_observed=[],
            known_devices=[], daily_file_access_mean=p["file_mean"], daily_file_access_std=p["file_std"],
            daily_volume_history=[], typical_max_sensitivity=1, role_sensitivity_ceiling=2,
            daily_email_mean=p["email_mean"], daily_email_std=p["email_std"], department=department,
            dept_file_access_mean=p["file_mean"], dept_file_access_std=p["file_std"],
            dept_email_mean=p["email_mean"], dept_email_std=p["email_std"],
            dept_login_hour_mean=p["hour_mean"], dept_login_hour_std=2.5, dept_usb_rate=p["usb_rate"],
        )
        self.save(b)
        logger.info("Cold-start baseline created", extra={"user_id": user_id})
        return b

    # ── learning ──────────────────────────────────────────────────────────
    def update_after_scoring(self, user_id: str, session: Mapping, score: float, update_threshold: float) -> str:
        """Score-gated update. Returns 'full', 'gated' or 'skipped'."""
        with self._lock:
            b = self.get(user_id)
            if b is None:
                return "skipped"
            b.recent_scores = (b.recent_scores + [round(float(score), 4)])[-7:]
            b.observation_days += 1
            if b.observation_days >= 5:
                b.cold_start = False
            status = "gated"
            if score < update_threshold:
                status = "full"
                b.login_hours_observed = (b.login_hours_observed + [session.get("hour_of_day", 9)])[-240:]
                b.login_hour_mean = circular_mean(b.login_hours_observed)
                b.login_hour_std = circular_std(b.login_hours_observed)
                b.daily_volume_history = (b.daily_volume_history + [float(session.get("file_count", 0))])[-30:]
                b.daily_file_access_mean = float(np.mean(b.daily_volume_history))
                b.daily_file_access_std = max(float(np.std(b.daily_volume_history)), 1.0)
                pc = session.get("pc") or ""
                if pc and pc not in b.known_devices:
                    b.known_devices.append(pc)
            b.last_updated = str(date.today())
            self.save(b)
            return status
