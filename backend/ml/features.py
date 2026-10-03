"""
Feature engineering (no model code here).

1. Behaviour features  – 18 per-session features used by the insider-threat
   Isolation Forest (trained on CERT r4.2). Order and maths are unchanged from
   the original project so the shipped model keeps working.
2. Rule signals        – human-readable detection rules + the rule score used
   by the hybrid scoring mode.
3. Network features    – 34 UNSW-NB15-style features for the network model.
"""
from __future__ import annotations

import math
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Iterable, List, Mapping

import numpy as np

if TYPE_CHECKING:  # pragma: no cover
    from ml.baselines import UserBaseline

# ── Session schema ─────────────────────────────────────────────────────────
# A "session" is one user's activity window (CERT definition: logon → logoff).
SESSION_FIELDS: Dict[str, type] = {
    "user_id": str,
    "pc": str,
    "session_start": str,
    "hour_of_day": int,
    "is_weekend": int,
    "is_outside_hours": int,
    "duration_minutes": float,
    "file_count": int,
    "max_sensitivity": int,
    "usb_connected": int,
    "usb_first_time": int,
    "email_count": int,
    "has_ext_email": int,
    "visited_exfil_domain": int,
    "visited_jobsearch_domain": int,
}

EXFIL_DOMAINS = {
    "wikileaks.org", "dropbox.com", "mega.nz", "wetransfer.com", "sendspace.com",
    "mediafire.com", "pastebin.com", "anonfiles.com",
}
JOBSEARCH_DOMAINS = {
    "linkedin.com", "indeed.com", "glassdoor.com", "monster.com",
    "careerbuilder.com", "ziprecruiter.com",
}


def normalize_session(raw: Mapping) -> dict:
    """Coerce a session dict to the schema above (missing numeric fields → 0)."""
    out = {}
    for key, typ in SESSION_FIELDS.items():
        value = raw.get(key)
        if typ is str:
            out[key] = "" if value is None else str(value)
        elif typ is int:
            out[key] = int(value or 0)
        else:
            out[key] = float(value or 0.0)
    if not out["duration_minutes"]:
        out["duration_minutes"] = 1.0
    return out


# ── Behaviour features ────────────────────────────────────────────────────
def circular_distance(hour: float, mean_hour: float) -> float:
    diff = abs(hour - mean_hour) % 24
    return min(diff, 24 - diff)


def score_trend(scores: List[float]) -> float:
    """Slope of the user's recent anomaly scores, clipped to [-1, 1]."""
    if len(scores) < 2:
        return 0.0
    n = len(scores)
    x_mean = (n - 1) / 2
    y_mean = sum(scores) / n
    num = sum((i - x_mean) * (y - y_mean) for i, y in enumerate(scores))
    den = sum((i - x_mean) ** 2 for i in range(n))
    return float(max(-1.0, min(1.0, num / den))) if den else 0.0


def behavior_features(session: Mapping, b: "UserBaseline") -> Dict[str, float]:
    """The 18 features expected by models/behavior/isolation_forest.joblib."""
    hour = session["hour_of_day"]
    files = session["file_count"]
    duration = max(float(session.get("duration_minutes", 1.0)), 1.0)
    f_std = max(b.daily_file_access_std, 1.0)
    d_std = max(b.dept_file_access_std, 1.0)
    pc = session.get("pc") or ""
    return {
        "hour_of_day": float(hour),
        "hour_deviation": circular_distance(hour, b.login_hour_mean),
        "is_weekend": float(session.get("is_weekend", 0)),
        "is_outside_hours": float(session.get("is_outside_hours", 0)),
        "is_new_device": float(bool(pc) and pc not in set(b.known_devices)),
        "file_count": float(files),
        "file_count_zscore": (files - b.daily_file_access_mean) / f_std,
        "files_per_minute": files / duration,
        "max_sensitivity": float(session.get("max_sensitivity", 0)),
        "sensitivity_above_ceil": float(session.get("max_sensitivity", 0) > b.role_sensitivity_ceiling),
        "email_count": float(session.get("email_count", 0)),
        "has_ext_email": float(session.get("has_ext_email", 0)),
        "usb_connected": float(session.get("usb_connected", 0)),
        "usb_first_time": float(session.get("usb_first_time", 0)),
        "visited_exfil_domain": float(session.get("visited_exfil_domain", 0)),
        "visited_jobsearch_domain": float(session.get("visited_jobsearch_domain", 0)),
        "recent_score_trend": score_trend(b.recent_scores),
        "file_count_peer_zscore": (files - b.dept_file_access_mean) / d_std,
    }


# ── Dimension scores + rules ───────────────────────────────────────────────
RULE_DESCRIPTIONS: Dict[str, str] = {
    "login_outside_normal_hours": "Session started at an unusual hour compared with the user's historical login pattern.",
    "unknown_device": "Activity from a workstation not in the user's list of known devices — possible account misuse.",
    "file_download_volume_extreme": "File access volume far above the user's baseline (z-score > 4) — consistent with bulk collection before exfiltration.",
    "high_sensitivity_file_access": "Files above the user's normal sensitivity level were accessed.",
    "usb_device_connected": "A removable USB device was connected during the session (MITRE T1052.001 if data is copied).",
    "usb_first_time": "First USB connection recorded for this user — a strong insider-exfiltration signal in CERT scenario 1.",
    "external_email_recipient": "Email sent to a recipient outside the organisation (possible data sharing, CERT scenario 2).",
    "exfil_domain_visited": "Visited a known exfiltration / leak site (e.g. wikileaks.org, file-sharing services).",
    "jobsearch_domain_visited": "Visited a job-search site — pre-resignation indicator in CERT scenario 2.",
    # network rules
    "isolation_forest_anomaly": "Network Isolation Forest marked the traffic window as anomalous.",
    "catboost_attack": "Supervised CatBoost classifier (UNSW-NB15) classified the window as an attack.",
    "amplification_ratio": "Response bytes far exceed request bytes — reflection/amplification DoS pattern (T1498.002).",
    "syn_no_response": "Many outbound TCP attempts with no response — SYN flood pattern (T1498.001).",
    "known_attack_port": "Traffic to a port commonly abused for amplification attacks.",
    "port_scan_pattern": "One source contacted many distinct destination ports — network service scanning (T1046).",
}


def dimension_scores(session: Mapping, b: "UserBaseline") -> Dict[str, float]:
    """Interpretable 0–1 scores per behaviour dimension (unchanged formulas)."""
    hour_dist = circular_distance(session["hour_of_day"], b.login_hour_mean)
    time_s = min(hour_dist / max(b.login_hour_std, 0.5) / 8.0, 1.0)
    pc = session.get("pc") or ""
    device_s = 1.0 if pc and pc not in set(b.known_devices) else 0.0
    z = (session["file_count"] - b.daily_file_access_mean) / max(b.daily_file_access_std, 1.0)
    volume_s = 0.0 if z <= 0 else min(z / 8.0, 1.0)
    obs = session.get("max_sensitivity", 0)
    sens_s = 1.0 if obs > b.role_sensitivity_ceiling else (0.5 if obs > b.typical_max_sensitivity else 0.0)
    return {"time": round(time_s, 4), "device": device_s, "volume": round(volume_s, 4), "sensitivity": sens_s}


def triggered_rules(session: Mapping, dims: Mapping[str, float]) -> List[str]:
    rules = []
    if dims["time"] > 0.5:
        rules.append("login_outside_normal_hours")
    if dims["device"] > 0:
        rules.append("unknown_device")
    if dims["volume"] > 0.5:
        rules.append("file_download_volume_extreme")
    if dims["sensitivity"] > 0:
        rules.append("high_sensitivity_file_access")
    if session.get("usb_connected"):
        rules.append("usb_device_connected")
    if session.get("usb_first_time"):
        rules.append("usb_first_time")
    if session.get("has_ext_email"):
        rules.append("external_email_recipient")
    if session.get("visited_exfil_domain"):
        rules.append("exfil_domain_visited")
    if session.get("visited_jobsearch_domain"):
        rules.append("jobsearch_domain_visited")
    return rules


def rule_score(session: Mapping, weights: Mapping[str, float]) -> float:
    """Weighted sum of binary session signals, clipped to [0, 1] (hybrid mode)."""
    total = sum(float(weights.get(k, 0.0)) * float(bool(session.get(k, 0))) for k in weights)
    return float(min(max(total, 0.0), 1.0))


# ── Network features (UNSW-NB15 column order) ──────────────────────────────
NETWORK_FEATURE_NAMES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", "is_sm_ips_ports",
]
_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
_SERVICE = {21: 2, 22: 8, 25: 9, 53: 1, 80: 3, 443: 3}
_STATE = {"tcp": 1, "udp": 0}


def network_features(connections: Iterable[Mapping]) -> np.ndarray:
    """Approximate the 34 UNSW-NB15 flow features from a window of connections.

    Each connection needs: protocol, src_ip, dst_ip, src_port, dst_port,
    bytes_sent, bytes_received, timestamp. Host collectors (psutil) cannot see
    packet-level fields, so those are 0 — see README › Limitations.
    """
    conns = list(connections)
    if not conns:
        return np.zeros(len(NETWORK_FEATURE_NAMES), dtype=np.float32)

    stamps = []
    for c in conns:
        try:
            stamps.append(datetime.fromisoformat(str(c.get("timestamp"))))
        except (TypeError, ValueError):
            pass
    dur = (max(stamps) - min(stamps)).total_seconds() if len(stamps) >= 2 else 0.0
    sent = [float(c.get("bytes_sent") or 0) for c in conns]
    recv = [float(c.get("bytes_received") or 0) for c in conns]
    proto_raw = str(conns[0].get("protocol") or "tcp").lower()
    dst_port = int(conns[0].get("dst_port") or 0)
    n = float(len(conns))
    sb, db = sum(sent), sum(recv)
    vec = [
        dur, _PROTO.get(proto_raw, 6), _SERVICE.get(dst_port, 0), _STATE.get(proto_raw, 2),
        n, n, sb, db,
        (2 * n) / dur if dur > 0 else 0.0,
        sb * 8 / dur if dur > 0 else 0.0, db * 8 / dur if dur > 0 else 0.0,
        0.0, 0.0, dur / n, dur / n,
        float(np.std(sent)) if len(sent) > 1 else 0.0, float(np.std(recv)) if len(recv) > 1 else 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        sb / n, db / n, 0.0, 0.0,
        float(len({c.get("dst_port") for c in conns})), float(len({c.get("src_port") for c in conns})),
        1.0 if dst_port == 21 else 0.0, 0.0, 0.0,
        1.0 if (len({c.get("src_ip") for c in conns}) == 1 and len({c.get("dst_ip") for c in conns}) == 1
                and len({c.get("dst_port") for c in conns}) == 1) else 0.0,
    ]
    arr = np.asarray(vec, dtype=np.float32)
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


def hour_bucket_label(hour: int) -> str:
    return "night" if hour < 6 else "morning" if hour < 12 else "afternoon" if hour < 18 else "evening"


def safe_float(value, default: float = 0.0) -> float:
    try:
        v = float(value)
        return default if math.isnan(v) or math.isinf(v) else v
    except (TypeError, ValueError):
        return default
