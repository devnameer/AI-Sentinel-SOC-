"""
System health: every dependency reports its own status and, when broken, a hint
telling the student exactly what to do (e.g. "ollama serve").
"""
from __future__ import annotations

import platform
import sys
import threading
import time
from typing import Any, Dict

from django.db import connection

from agents.resources import get_baseline_store, get_q_agent
from api.stream import stream_worker
from core.auth import auth_enabled
from core.config import get_config
from core.llm import get_llm_client
from ml.behavior_model import get_behavior_model
from ml.datasets import get_replay_dataset
from ml.network_model import get_network_model
from rag.retriever import get_retriever

_cache: Dict[str, Any] = {}
_lock = threading.Lock()
LLM_CACHE_SECONDS = 15


def _llm_health() -> Dict[str, Any]:
    with _lock:
        hit = _cache.get("llm")
        if hit and time.monotonic() - hit[0] < LLM_CACHE_SECONDS:
            return hit[1]
    client = get_llm_client()
    data = {**client.describe(), **client.health()}
    data["status"] = (data.get("primary") or {}).get("status", "unknown")
    with _lock:
        _cache["llm"] = (time.monotonic(), data)
    return data


def _db_health() -> Dict[str, Any]:
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
        return {"status": "online", "engine": connection.vendor}
    except Exception as exc:
        return {"status": "offline", "engine": connection.vendor, "error": str(exc)}


def system_health() -> Dict[str, Any]:
    cfg = get_config()
    llm = _llm_health()
    behavior = get_behavior_model().status()
    network = get_network_model().status()
    try:
        baselines = {"status": "ready", "users": len(get_baseline_store())}
    except Exception as exc:
        baselines = {"status": "error", "error": str(exc)}
    q = get_q_agent().stats()
    components = {
        "database": _db_health(),
        "llm": llm,
        "behavior_model": behavior,
        "network_model": network,
        "baselines": baselines,
        "rl_policy": {"status": "trained" if q["trained_states"] else "untrained (rule fallback)", **q},
        "retrieval": get_retriever().status(),
        "replay_dataset": get_replay_dataset().status(),
        "mcp": {"status": "ready", "transport": cfg.mcp.transport},
        "twilio": {"status": "enabled" if cfg.notifications.twilio.enabled else "disabled (optional)",
                   "configured": bool(cfg.secrets.twilio_account_sid and cfg.secrets.twilio_auth_token)},
        "stream": stream_worker.status(),
    }
    primary = (llm.get("primary") or {}).get("status")
    critical_ok = components["database"]["status"] == "online" and behavior["status"] == "loaded"
    overall = "healthy" if critical_ok and primary in ("online", "disabled") else \
        "degraded" if critical_ok else "unhealthy"
    warnings = []
    if not auth_enabled():
        warnings.append("API authentication is disabled (SOC_API_TOKEN not set) — fine for localhost only.")
    if primary not in ("online", "disabled"):
        p = llm.get("primary") or {}
        warnings.append(f"LLM provider {p.get('provider')}: {p.get('status')} — {p.get('hint') or p.get('detail')}. "
                        "Agents fall back to templates/policy.")
    if network["status"] != "loaded":
        warnings.append("Network model is running without CatBoost (IF-only) — pip install catboost.")
    warnings += [f"Behaviour model: {w}" for w in behavior.get("warnings", [])]
    return {
        "status": overall, "warnings": warnings, "components": components,
        "environment": {"app_env": cfg.app.environment, "python": sys.version.split()[0],
                        "platform": platform.system(), "auth_enabled": auth_enabled()},
    }
