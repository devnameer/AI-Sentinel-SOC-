"""
Data loading + preprocessing for the CERT r4.2 insider-threat sessions.

Files (data/datasets/, see the README there for provenance):
* cert_r42_sessions.csv.gz – 133,270 labelled-able user sessions (test period)
* cert_insiders.csv        – CERT answer key: malicious users + time windows

Label used for evaluation / RL pre-training: a session is "insider" (1) when
the user is listed for dataset 4.2 and the session falls inside that user's
malicious time window. This window-level label is approximate (not every
session in the window is malicious), which makes precision look lower than
it is — keep that in mind when reading the metrics.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Iterator, List, Optional

import pandas as pd

from core.config import AppConfig, get_config
from ml.features import SESSION_FIELDS


def load_sessions(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, compression="infer")
    missing = [c for c in SESSION_FIELDS if c not in df.columns]
    if missing:
        raise ValueError(f"dataset {path} is missing columns: {missing}")
    df["session_start"] = pd.to_datetime(df["session_start"])
    return df


def add_insider_labels(df: pd.DataFrame, insiders_path: Path, dataset: str = "4.2") -> pd.DataFrame:
    ins = pd.read_csv(insiders_path)
    ins = ins[ins["dataset"].astype(str) == dataset]
    df = df.copy()
    df["insider"] = 0
    for row in ins.itertuples():
        start = pd.to_datetime(row.start, format="mixed").floor("D")
        end = pd.to_datetime(row.end, format="mixed").ceil("D")
        mask = (df["user_id"] == row.user) & (df["session_start"] >= start) & (df["session_start"] <= end)
        df.loc[mask, "insider"] = 1
    return df


def row_to_session(row) -> dict:
    data = row._asdict() if hasattr(row, "_asdict") else dict(row)
    session = {k: (data[k].item() if hasattr(data[k], "item") else data[k]) for k in SESSION_FIELDS if k in data}
    ts = data["session_start"]
    session["session_start"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    if "insider" in data:
        session["ground_truth_insider"] = bool(data["insider"])
    return session


class ReplayDataset:
    """Cycles through the CERT sessions in a stratified order for live demos.

    Roughly 1 in ``signal_every`` sessions is drawn from sessions that contain a
    risk signal (USB, exfil site, …) so the demo stream is not 99 % idle logons.
    The mix is reported in the UI — nothing is relabelled or altered.
    """

    def __init__(self, cfg: Optional[AppConfig] = None, seed: int = 7, signal_every: int = 3):
        self.cfg = cfg or get_config()
        self._lock = threading.Lock()
        self._df: Optional[pd.DataFrame] = None
        self._order: List[int] = []
        self._pos = 0
        self.seed = seed
        self.signal_every = signal_every
        self.error: Optional[str] = None

    def _ensure(self) -> None:
        if self._df is not None or self.error:
            return
        try:
            df = load_sessions(self.cfg.path(self.cfg.data.replay_dataset_path))
            df = add_insider_labels(df, self.cfg.path(self.cfg.data.insiders_path))
        except FileNotFoundError as exc:
            self.error = f"Replay dataset not found: {exc.filename}"
            return
        signal = (df["usb_connected"] | df["visited_exfil_domain"] | df["visited_jobsearch_domain"]
                  | df["has_ext_email"]).astype(bool)
        sig_idx = df.index[signal].to_series().sample(frac=1, random_state=self.seed).tolist()
        plain_idx = df.index[~signal].to_series().sample(frac=1, random_state=self.seed).tolist()
        order, si, pi = [], 0, 0
        while si < len(sig_idx) or pi < len(plain_idx):
            if len(order) % self.signal_every == 0 and si < len(sig_idx):
                order.append(sig_idx[si]); si += 1
            elif pi < len(plain_idx):
                order.append(plain_idx[pi]); pi += 1
            else:
                order.append(sig_idx[si]); si += 1
        self._df, self._order = df, order

    def status(self) -> dict:
        self._ensure()
        if self.error:
            return {"status": "unavailable", "error": self.error}
        return {"status": "ready", "sessions": len(self._df), "position": self._pos,
                "insider_sessions": int(self._df["insider"].sum()), "users": int(self._df["user_id"].nunique())}

    def next_sessions(self, n: int) -> List[dict]:
        self._ensure()
        if self.error:
            raise FileNotFoundError(self.error)
        with self._lock:
            out = []
            for _ in range(n):
                idx = self._order[self._pos % len(self._order)]
                self._pos += 1
                out.append(row_to_session(self._df.loc[idx]))
            return out

    def iter_frame(self) -> Iterator[dict]:
        self._ensure()
        for row in self._df.itertuples(index=False):
            yield row_to_session(row)


_replay: Optional[ReplayDataset] = None


def get_replay_dataset() -> ReplayDataset:
    global _replay
    if _replay is None:
        _replay = ReplayDataset()
    return _replay
