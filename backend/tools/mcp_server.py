"""
SOC MCP tool server (Model Context Protocol).

One server exposes every tool the agents may use. All tools are READ-ONLY and
allow-listed — there is no code-execution tool (the original project's
"sandboxed" Python executor was removed: regex sandboxes are bypassable).

Run standalone (e.g. to connect Claude Desktop, MCP Inspector, or with
``mcp.transport: stdio`` in config.yaml):

    cd backend
    python -m tools.mcp_server
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sentinel-soc-tools")


def _setup_django() -> None:
    """Tools that read incident history need Django; set it up when run standalone."""
    backend_dir = Path(__file__).resolve().parents[1]
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "soc_platform.settings")
    # FastMCP runs sync tools inside its event loop. This standalone process makes only
    # short, sequential read-only queries, so Django's async-safety guard can be relaxed
    # here (and only here — the web server never sets this).
    os.environ.setdefault("DJANGO_ALLOW_ASYNC_UNSAFE", "true")
    import django
    from django.apps import apps

    if not apps.ready:
        django.setup()


@mcp.tool()
def list_collectors() -> dict:
    """List host data collectors, what they collect and whether they run on this host."""
    from tools.collectors import list_collectors as _list

    return {"collectors": _list()}


@mcp.tool()
def collect_host_events(collectors: List[str], max_events: int = 300) -> dict:
    """Run allow-listed read-only host collectors (system, process, network, file, …) and return events."""
    from tools.collectors import COLLECTORS, run_collector

    max_events = max(1, min(int(max_events), 1000))
    results, events = [], []
    for name in collectors[:10]:
        if name not in COLLECTORS:
            results.append({"collector": name, "ok": False, "error": "not in allow-list"})
            continue
        r = run_collector(name, max_events=max_events)
        events.extend(r.pop("events", []))
        results.append(r)
    return {"results": results, "events": events[:max_events], "total": len(events)}


@mcp.tool()
def get_user_baseline(user_id: str) -> dict:
    """Return the behavioural baseline (normal hours, devices, file volume…) for a user."""
    from agents.resources import get_baseline_store

    b = get_baseline_store().get(user_id[:64])
    return b.summary() if b else {"user_id": user_id, "found": False}


@mcp.tool()
def get_user_incident_history(user_id: str, hours: int = 24) -> dict:
    """Count recent analyses and incidents for a user (used for repeat-offender context)."""
    from datetime import timedelta

    from django.utils import timezone

    from api.models import Analysis, Incident

    since = timezone.now() - timedelta(hours=max(1, min(int(hours), 24 * 30)))
    analyses = Analysis.objects.filter(user_id=user_id[:64], created_at__gte=since)
    return {
        "user_id": user_id,
        "window_hours": hours,
        "analyses": analyses.count(),
        "medium_or_high": analyses.filter(risk_level__in=["MEDIUM", "HIGH"]).count(),
        "open_incidents": Incident.objects.filter(analysis__user_id=user_id[:64],
                                                  status__in=["open", "awaiting_approval"]).count(),
    }


@mcp.tool()
def explain_rules(rule_ids: List[str]) -> dict:
    """Plain-language explanation of triggered detection rules."""
    from ml.features import RULE_DESCRIPTIONS

    return {r: RULE_DESCRIPTIONS.get(r, "No description available.") for r in rule_ids[:20]}


@mcp.tool()
def search_knowledge(query: str, k: int = 3) -> dict:
    """Search the local cybersecurity knowledge base (MITRE ATT&CK, CERT scenarios, playbooks)."""
    from rag.retriever import get_retriever

    return {"results": get_retriever().search(query[:500], k=max(1, min(int(k), 10)))}


@mcp.tool()
def get_risk_policy() -> dict:
    """Current risk thresholds, guardrails and approval policy."""
    from core.config import get_config

    cfg = get_config()
    return {"thresholds": cfg.risk.thresholds, "min_action": cfg.risk.min_action,
            "max_action": cfg.risk.max_action, "require_approval_for": cfg.response.require_approval_for,
            "auto_execute_high_risk": cfg.response.auto_execute_high_risk,
            "max_llm_adjustment": cfg.agents.risk_agent.max_llm_adjustment}


# The same functions, for the in-process transport (tools/mcp_client.py).
TOOL_FUNCTIONS = {f.__name__: f for f in (list_collectors, collect_host_events, get_user_baseline,
                                          get_user_incident_history, explain_rules, search_knowledge,
                                          get_risk_policy)}


def main() -> None:
    _setup_django()
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
