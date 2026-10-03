"""
Application services: glue between the API, the agent pipeline and the database.

Views stay thin; everything that changes state lives here so it can be tested
without HTTP.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Dict, List, Optional

from django.db import transaction
from django.db.models import Avg, Count, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from agents.attacker_agent import SCENARIOS, AttackerAgent
from agents.base import AGENT_INFO
from agents.data_agent import DataAgent
from agents.pipeline import PIPELINE_ORDER, run_pipeline
from agents.resources import get_q_agent
from api.models import AgentRun, Analysis, Event, Incident, Simulation
from core.config import get_config
from ml.datasets import get_replay_dataset
from ml.q_learning import encode_state, reward_from_analyst

logger = logging.getLogger("soc.services")


class ServiceError(Exception):
    """Expected, user-facing failure (bad input, unavailable dependency)."""

    def __init__(self, message: str, code: str = "service_error", status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


# ── persistence of one pipeline run ────────────────────────────────────────
def _aware(value: Any) -> datetime:
    dt = parse_datetime(str(value)) if value else None
    if dt is None:
        return timezone.now()
    return dt if timezone.is_aware(dt) else dt.replace(tzinfo=dt_timezone.utc)


@transaction.atomic
def persist_run(request: Dict[str, Any], state: Dict[str, Any], simulation: Optional[Simulation] = None) -> Analysis:
    b, r, resp = state.get("behavior") or {}, state.get("risk") or {}, state.get("response") or {}
    session = state.get("session") or {}
    analysis = Analysis.objects.create(
        source=state.get("source") or request.get("source", "manual"),
        kind=state.get("kind") or request.get("kind", "behavior"),
        user_id=str(b.get("user_id") or session.get("user_id") or "")[:128],
        device_id=str(b.get("device_id") or session.get("pc") or "")[:128],
        score=b.get("score"), flagged=bool(b.get("flagged")), verdict=b.get("verdict", ""),
        model=b.get("model", ""), triggered_rules=b.get("triggered_rules", []),
        threat_category=b.get("threat_category", ""), mitre_techniques=b.get("mitre_techniques", []),
        explanation=b.get("explanation", ""), explanation_source=b.get("explanation_source", ""),
        risk_score=r.get("risk_score"), risk_level=r.get("risk_level", ""), decision=r.get("decision", ""),
        action=resp.get("action", ""), execution=resp.get("execution", ""),
        is_simulated=request.get("source") == "attacker", ground_truth=state.get("ground_truth"),
        simulation=simulation, status="error" if state.get("halted") else "ok", errors=state.get("errors", []),
        details={"behavior": b, "risk": r, "response": resp, "session": session},
    )
    severity = analysis.risk_level
    Event.objects.bulk_create([
        Event(timestamp=_aware(e.get("timestamp")), source=str(e.get("source") or analysis.source)[:32],
              event_type=str(e.get("event_type", "unknown"))[:32], category=str(e.get("event_category", ""))[:32],
              user_id=str(e.get("user_id") or "")[:128], device_id=str(e.get("device_id") or "")[:128],
              resource=str(e.get("resource") or "")[:512], metadata=e.get("metadata") or {},
              is_simulated=analysis.is_simulated, severity=severity, analysis=analysis)
        for e in (state.get("events") or [])[:500]
    ])
    AgentRun.objects.bulk_create([
        AgentRun(agent=t["agent"], started_at=_aware(t["started_at"]), duration_ms=t.get("duration_ms", 0),
                 status=t.get("status", "ok"), summary=str(t.get("summary", ""))[:300], error=t.get("error", ""),
                 analysis=analysis, details={"tool_calls": t.get("tool_calls", []), "llm": t.get("llm")})
        for t in state.get("trace", [])
    ])
    if resp.get("execution") in ("awaiting_approval", "auto_executed"):
        title = (f"{analysis.risk_level} · {analysis.threat_category.replace('_', ' ') or 'anomaly'} · "
                 f"{analysis.user_id or analysis.device_id}")
        incident = Incident.objects.create(
            analysis=analysis, title=title[:200], severity=analysis.risk_level,
            status=resp["execution"], recommended_action=resp.get("action", "ESCALATE"),
            final_action=resp.get("action", "") if resp["execution"] == "auto_executed" else "",
        )
        transaction.on_commit(lambda: notify_incident(incident.pk))
    return analysis


def execute_request(request: Dict[str, Any], simulation: Optional[Simulation] = None) -> Analysis:
    state = run_pipeline(request)
    return persist_run(request, state, simulation)


# ── ingestion ──────────────────────────────────────────────────────────────
def ingest(source: str, count: int = 1, collectors: Optional[List[str]] = None,
           session: Optional[dict] = None) -> Dict[str, Any]:
    if source == "manual":
        if not session:
            raise ServiceError("A 'session' object is required for manual ingestion.", "validation_error")
        return {"analyses": [execute_request({"source": "manual", "kind": "behavior", "session": session})]}
    if source == "replay":
        try:
            sessions = get_replay_dataset().next_sessions(count)
        except FileNotFoundError as exc:
            raise ServiceError(str(exc), "dataset_missing", 503) from exc
        analyses = [execute_request({"source": "replay", "kind": "behavior", "session": s,
                                     "ground_truth": s.pop("ground_truth_insider", None)}) for s in sessions]
        return {"analyses": analyses}
    if source == "host":
        agent = DataAgent()
        collected = agent.collect_host(collectors)
        requests = agent.build_requests(collected["events"], "host")
        if not requests:
            raise ServiceError("Host collectors returned no events (see 'collection' for per-collector errors).",
                               "no_events", 422)
        analyses = [execute_request(req) for req in requests[:10]]
        collected.pop("events", None)
        return {"analyses": analyses, "collection": collected}
    raise ServiceError(f"Unknown source '{source}'", "validation_error")


# ── attack simulation ──────────────────────────────────────────────────────
def simulate(scenario_id: Optional[str] = None, target_user: Optional[str] = None,
             seed: Optional[int] = None) -> Simulation:
    attacker = AttackerAgent(seed=seed)
    t0 = time.perf_counter()
    planner: Dict[str, Any] = {"method": "user_selected"}
    if not scenario_id:
        history = list(Simulation.objects.values("scenario_id", "status")[:200])
        scenario_id, planner = attacker.plan(history)
    if scenario_id not in SCENARIOS:
        raise ServiceError(f"Unknown scenario '{scenario_id}'", "validation_error")
    try:
        request = attacker.build(scenario_id, target_user)
    except Exception as exc:
        raise ServiceError(f"Could not build scenario: {exc}", "simulation_error", 500) from exc
    meta = request["simulation"]
    sim = Simulation.objects.create(
        scenario_id=scenario_id, name=meta["name"], kind=request["kind"], technique=meta["technique"],
        tactic=meta["tactic"], target=meta["target"], device=meta["device"],
        expected_malicious=meta["expected_malicious"], planner=planner,
    )
    AgentRun.objects.create(agent="attacker_agent", started_at=timezone.now(), status="ok",
                            duration_ms=round((time.perf_counter() - t0) * 1000, 1),
                            summary=f"{scenario_id} → {meta['target']} ({len(request['events'])} events)",
                            details={"planner": planner})
    try:
        analysis = execute_request(request, simulation=sim)
    except Exception as exc:
        sim.status, sim.error = "error", str(exc)
        sim.save(update_fields=["status", "error"])
        raise
    if analysis.status == "error":
        sim.status = "error"
        sim.error = "; ".join(analysis.errors)
    elif sim.expected_malicious:
        sim.status = "detected" if analysis.flagged else "missed"
    else:
        sim.status = "false_positive" if analysis.flagged else "correctly_ignored"
    sim.save(update_fields=["status", "error"])
    return sim


# ── human-in-the-loop decisions ────────────────────────────────────────────
@transaction.atomic
def decide_incident(incident_id: int, decision: str, note: str = "", actor: str = "analyst") -> Incident:
    try:
        incident = Incident.objects.select_for_update().select_related("analysis").get(pk=incident_id)
    except Incident.DoesNotExist as exc:
        raise ServiceError("Incident not found.", "not_found", 404) from exc
    if incident.status != "awaiting_approval":
        raise ServiceError(f"Incident is already '{incident.status}'.", "conflict", 409)
    approved = decision == "approve"
    incident.status = "approved" if approved else "denied"
    incident.final_action = incident.recommended_action if approved else "MONITOR"
    incident.decided_at, incident.decided_by, incident.decision_note = timezone.now(), actor[:64], note[:2000]
    incident.save()
    a = incident.analysis
    a.execution = "approved" if approved else "denied"
    a.save(update_fields=["execution"])
    logger.info("Incident decision", extra={"incident": incident.reference, "decision": decision,
                                            "action": incident.final_action,
                                            "note": "action recorded (simulated containment)"})
    cfg = get_config()
    if cfg.rl.learn_from_analyst_feedback:
        b = a.details.get("behavior", {})
        state = encode_state(a.risk_level, a.risk_score or 0.0, len(a.triggered_rules), bool(b.get("cold_start")))
        q = get_q_agent()
        q.update(state, incident.recommended_action, reward_from_analyst(approved))
        q.save()
    return incident


# ── notifications (optional Twilio SMS) ────────────────────────────────────
def notify_incident(incident_id: int) -> None:
    cfg = get_config()
    tw, s = cfg.notifications.twilio, cfg.secrets
    if not tw.enabled:
        return
    incident = Incident.objects.filter(pk=incident_id).first()
    if incident is None or incident.severity not in tw.notify_levels:
        return
    if not (s.twilio_account_sid and s.twilio_auth_token and s.twilio_from_number and s.twilio_to_number):
        incident.notification = {"channel": "twilio", "sent": False, "error": "TWILIO_* variables missing"}
        incident.save(update_fields=["notification"])
        return

    def send() -> None:
        try:
            from twilio.rest import Client

            msg = Client(s.twilio_account_sid, s.twilio_auth_token).messages.create(
                to=s.twilio_to_number, from_=s.twilio_from_number,
                body=f"[SOC] {incident.reference} {incident.title}. Recommended: {incident.recommended_action}. "
                     "Review on the dashboard.")
            result = {"channel": "twilio", "sent": True, "sid": msg.sid}
        except Exception as exc:  # optional integration — never break the pipeline
            result = {"channel": "twilio", "sent": False, "error": f"{type(exc).__name__}: {exc}"}
        Incident.objects.filter(pk=incident_id).update(notification=result)

    threading.Thread(target=send, daemon=True).start()


# ── read models for the dashboard ──────────────────────────────────────────
def overview(hours: int = 24) -> Dict[str, Any]:
    since = timezone.now() - timedelta(hours=hours)
    analyses = Analysis.objects.filter(created_at__gte=since)
    events = Event.objects.filter(ingested_at__gte=since)
    agg = analyses.aggregate(total=Count("id"), flagged=Count("id", filter=Q(flagged=True)),
                             avg_score=Avg("score"), avg_risk=Avg("risk_score"))
    risk_dist = Counter(analyses.values_list("risk_level", flat=True))
    actions = Counter(analyses.exclude(action="").values_list("action", flat=True))
    categories = Counter(analyses.filter(flagged=True).values_list("threat_category", flat=True))

    # hourly time series (python-side bucketing keeps it DB-agnostic)
    buckets: Dict[str, Dict[str, int]] = {}
    start = (timezone.now() - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
    for i in range(hours):
        buckets[(start + timedelta(hours=i)).isoformat()] = {"analyses": 0, "flagged": 0, "high": 0, "events": 0}
    for created, flagged, level in analyses.values_list("created_at", "flagged", "risk_level"):
        key = created.replace(minute=0, second=0, microsecond=0).isoformat()
        if key in buckets:
            buckets[key]["analyses"] += 1
            buckets[key]["flagged"] += int(flagged)
            buckets[key]["high"] += int(level == "HIGH")
    for ingested in events.values_list("ingested_at", flat=True):
        key = ingested.replace(minute=0, second=0, microsecond=0).isoformat()
        if key in buckets:
            buckets[key]["events"] += 1

    scores = list(analyses.exclude(score=None).values_list("score", flat=True)[:2000])
    histogram = [0] * 10
    for sc in scores:
        histogram[min(int(sc * 10), 9)] += 1
    sims = Simulation.objects.filter(created_at__gte=since)
    return {
        "window_hours": hours,
        "totals": {
            "events": events.count(), "analyses": agg["total"], "suspicious": agg["flagged"],
            "active_threats": Incident.objects.filter(status="awaiting_approval").count(),
            "blocked": analyses.filter(Q(action="BLOCK") & Q(execution__in=["approved", "auto_executed"])).count(),
            "escalated": analyses.filter(action="ESCALATE").count(),
            "incidents_open": Incident.objects.filter(status="awaiting_approval").count(),
            "simulations": sims.count(),
            "avg_anomaly_score": round(agg["avg_score"] or 0.0, 4),
            "avg_risk_score": round(agg["avg_risk"] or 0.0, 4),
        },
        "risk_distribution": {lvl: risk_dist.get(lvl, 0) for lvl in ("LOW", "MEDIUM", "HIGH")},
        "executions": dict(Counter(analyses.exclude(execution="").values_list("execution", flat=True))),
        "response_actions": {a: actions.get(a, 0) for a in ("ALLOW", "MONITOR", "ESCALATE", "BLOCK")},
        "threat_categories": dict(categories.most_common(8)),
        "timeline": [{"hour": k, **v} for k, v in buckets.items()],
        "score_histogram": [{"bucket": f"{i / 10:.1f}–{(i + 1) / 10:.1f}", "count": c} for i, c in enumerate(histogram)],
        "simulation_outcomes": dict(Counter(sims.values_list("status", flat=True))),
    }


def agents_status(hours: int = 24) -> List[Dict[str, Any]]:
    cfg = get_config()
    since = timezone.now() - timedelta(hours=hours)
    out = []
    for name in ["data_agent", "attacker_agent", "behavior_agent", "risk_agent", "response_agent"]:
        runs = AgentRun.objects.filter(agent=name)
        recent = runs.filter(started_at__gte=since)
        agg = recent.aggregate(n=Count("id"), errors=Count("id", filter=Q(status="error")),
                               avg_ms=Avg("duration_ms"))
        last = runs.first()
        enabled = getattr(getattr(cfg.agents, name), "enabled", True)
        if not enabled:
            status = "disabled"
        elif last is None:
            status = "idle"
        elif last.status == "error":
            status = "error"
        elif timezone.now() - last.started_at < timedelta(minutes=2):
            status = "active"
        else:
            status = "idle"
        llm_feature = {"data_agent": "data_tool_selection", "behavior_agent": "behavior_explanation",
                       "risk_agent": "risk_assessment", "response_agent": "response_summary",
                       "attacker_agent": "attack_planning"}[name]
        out.append({
            "name": name, **AGENT_INFO[name], "enabled": enabled, "status": status,
            "llm_feature_enabled": getattr(cfg.llm.features, llm_feature),
            "processed": agg["n"], "errors": agg["errors"],
            "avg_latency_ms": round(agg["avg_ms"] or 0.0, 1),
            "last_activity": last.started_at.isoformat() if last else None,
            "last_summary": last.summary if last else "",
            "last_error": runs.filter(status="error").values_list("error", flat=True).first() or "",
            "pipeline_position": PIPELINE_ORDER.index(name) if name in PIPELINE_ORDER else None,
        })
    return out
