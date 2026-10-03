"""
Network-traffic model — inference only.

Two-stage hybrid trained on UNSW-NB15 (original project, unchanged artefacts):
    stage 1  Isolation Forest   – unsupervised anomaly score
    stage 2  CatBoost           – supervised attack probability
    model score = if_weight·IF + catboost_weight·CatBoost

On top of the model, deterministic verification rules (kept from the original
"network scorer") confirm, downgrade or reject model flags, and a few
unambiguous attack patterns (amplification, SYN flood, port scan) produce a
rule score.  final = max(verified model score, rule score).

CatBoost is optional: without it the model runs in IF-only "degraded" mode and
reports that in status().
"""
from __future__ import annotations

import logging
import threading
import warnings
from typing import Dict, List, Mapping, Optional

import numpy as np

from core.config import AppConfig, get_config
from ml.features import network_features

logger = logging.getLogger("soc.ml.network")

AMPLIFICATION_PORTS = {53: "DNS", 123: "NTP", 161: "SNMP", 389: "LDAP", 1900: "SSDP", 137: "NetBIOS",
                       111: "Portmap", 69: "TFTP", 1433: "MSSQL"}
BENIGN_PORTS = {80, 443, 8080, 8443, 22, 25, 587, 993, 995}


class NetworkModel:
    def __init__(self, cfg: Optional[AppConfig] = None):
        self.cfg = cfg or get_config()
        self._lock = threading.Lock()
        self._loaded = False
        self.scaler = self.iso = self.cat = None
        self.errors: Dict[str, str] = {}

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            s = self.cfg.ml.network
            try:
                import joblib

                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    self.scaler = joblib.load(self.cfg.path(s.scaler_path))
                    self.iso = joblib.load(self.cfg.path(s.isolation_forest_path))
            except Exception as exc:
                self.errors["isolation_forest"] = f"{type(exc).__name__}: {exc}"
            try:
                from catboost import CatBoostClassifier  # optional dependency

                cat = CatBoostClassifier()
                cat.load_model(str(self.cfg.path(s.catboost_path)))
                self.cat = cat
            except ImportError:
                self.errors["catboost"] = "catboost not installed (pip install catboost) — IF-only mode"
            except Exception as exc:
                self.errors["catboost"] = f"{type(exc).__name__}: {exc}"
            for k, v in self.errors.items():
                logger.warning("Network model component unavailable", extra={"component": k, "error": v})
            self._loaded = True

    def status(self) -> dict:
        self._load()
        if self.iso is None:
            state = "unavailable"
        elif self.cat is None:
            state = "degraded"
        else:
            state = "loaded"
        return {"name": "network_if_catboost", "status": state, "errors": self.errors,
                "components": {"isolation_forest": self.iso is not None, "catboost": self.cat is not None},
                "threshold": self.cfg.ml.network.anomaly_threshold}

    def score(self, connections: List[Mapping]) -> dict:
        self._load()
        s = self.cfg.ml.network
        feats = network_features(connections)
        if_score = cat_prob = None
        stage1_flag = False
        # The models were trained on flow records WITH byte counts (UNSW-NB15). Host snapshots from
        # psutil have none; feeding zeros produces confident nonsense, so the ML stage is skipped.
        has_bytes = any(c.get("bytes_sent") is not None or c.get("bytes_received") is not None for c in connections)
        if has_bytes and self.iso is not None and self.scaler is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                x = self.scaler.transform(feats.reshape(1, -1))
                stage1_flag = int(self.iso.predict(x)[0]) == -1
                if_score = float(np.clip(1.0 - (float(self.iso.score_samples(x)[0]) + 0.5), 0.0, 1.0))
                if self.cat is not None:
                    cat_prob = float(self.cat.predict_proba(x)[0][1])
        if if_score is None:
            model_score = 0.0
        elif cat_prob is None:
            model_score = if_score
        else:
            model_score = s.if_weight * if_score + s.catboost_weight * cat_prob
        model_flag = model_score >= s.anomaly_threshold or (stage1_flag and (cat_prob or 0) >= 0.5)

        verification = verify_model_flag(model_score, model_flag, connections)
        rules, r_score, label, mitre = network_rules(connections)
        final = max(verification["score"], r_score)
        flagged = final >= s.anomaly_threshold
        triggered = list(rules)
        if stage1_flag:
            triggered.insert(0, "isolation_forest_anomaly")
        if cat_prob is not None and cat_prob >= 0.5:
            triggered.insert(0, "catboost_attack")
        return {
            "score": round(final, 4),
            "flagged": flagged,
            "threshold": s.anomaly_threshold,
            "model_score": round(model_score, 4),
            "if_score": None if if_score is None else round(if_score, 4),
            "catboost_probability": None if cat_prob is None else round(cat_prob, 4),
            "rule_score": round(r_score, 4),
            "verification": verification["verdict"],
            "triggered_rules": triggered,
            "attack_label": label if flagged else None,
            "mitre_technique": mitre if flagged else None,
            "mode": "hybrid" if cat_prob is not None else ("if_only" if if_score is not None else
                                                           "rules_only" if has_bytes else "rules_only_no_byte_counts"),
            "connections": len(connections),
        }


def verify_model_flag(model_score: float, model_flag: bool, conns: List[Mapping]) -> dict:
    """Original rule-based verification: confirm / downgrade / reject a model flag."""
    if not conns or not model_flag:
        return {"verdict": "clean", "score": model_score}
    first = conns[0]
    port = int(first.get("dst_port") or 0)
    proto = str(first.get("protocol") or "tcp").upper()
    if any(c.get("bytes_sent") is None or c.get("bytes_received") is None for c in conns):
        return {"verdict": "unverifiable (no byte counts)", "score": model_score * 0.6}
    sent = sum(float(c.get("bytes_sent") or 0) for c in conns)
    recv = sum(float(c.get("bytes_received") or 0) for c in conns)
    signal = counter = 0.0
    if sent > 0:
        ratio = recv / sent
        signal += 0.5 if ratio > 50 else 0.3 if ratio > 10 else 0.1 if ratio > 3 else 0.0
    elif recv == 0 and proto == "TCP":
        signal += 0.4
    if port in AMPLIFICATION_PORTS:
        signal += 0.4
    if proto == "UDP" and recv > 100_000:
        signal += 0.2
    if port in BENIGN_PORTS and proto == "TCP":
        counter += 0.4
        if sent > 0 and recv / sent < 5:
            counter += 0.3
    if sent > 100 and recv > 100:
        counter += 0.1
    net = signal - counter
    if net >= 0.5:
        return {"verdict": "confirmed", "score": model_score}
    if net >= 0.1:
        return {"verdict": "downgraded", "score": model_score * 0.6}
    return {"verdict": "rejected", "score": model_score * 0.2}


def network_rules(conns: List[Mapping]) -> tuple[List[str], float, Optional[str], Optional[str]]:
    """Deterministic, explainable network detections. Returns (rules, score, label, mitre)."""
    if not conns:
        return [], 0.0, None, None
    rules: List[str] = []
    score = 0.0
    label = mitre = None
    tcp = [c for c in conns if str(c.get("protocol", "")).upper() == "TCP"]
    ports_per_pair: Dict[tuple, set] = {(): set()}
    for c in conns:
        if str(c.get("dst_ip", "")).startswith(("127.", "::1")):
            continue  # local services talking to each other are not a scan
        ports_per_pair.setdefault((str(c.get("src_ip")), str(c.get("dst_ip"))), set()).add(c.get("dst_port"))
    if max(len(p) for p in ports_per_pair.values()) >= 15:  # many ports on ONE target host
        rules.append("port_scan_pattern")
        score, label, mitre = max(score, 0.75), "Port_Scan", "T1046"
    udp_amp = [c for c in conns if str(c.get("protocol", "")).upper() == "UDP"
               and int(c.get("dst_port") or 0) in AMPLIFICATION_PORTS]
    if udp_amp:
        sent = sum(float(c.get("bytes_sent") or 0) for c in udp_amp)
        recv = sum(float(c.get("bytes_received") or 0) for c in udp_amp)
        if sent > 0 and recv / sent > 10 and recv > 50_000:
            port = int(udp_amp[0].get("dst_port") or 0)
            rules += ["amplification_ratio", "known_attack_port"]
            score = max(score, 0.85)
            label, mitre = f"DrDoS_{AMPLIFICATION_PORTS[port]}", "T1498.002"
    silent = [c for c in tcp if c.get("bytes_received") == 0]  # None = unknown, not "no response"
    flood_ports = {c.get("dst_port") for c in silent}
    if len(silent) >= 10 and len(silent) / max(len(tcp), 1) > 0.8 and len(flood_ports) <= 2:
        rules.append("syn_no_response")
        if score < 0.8:
            label, mitre = "SYN_Flood", "T1498.001"
        score = max(score, 0.8)
    return rules, score, label, mitre


_instance: Optional[NetworkModel] = None


def get_network_model() -> NetworkModel:
    global _instance
    if _instance is None:
        _instance = NetworkModel()
    return _instance
