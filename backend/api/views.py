"""
REST API v1. Views validate input, call api/services.py and serialise output.
Errors always use the shape produced by core.errors.api_exception_handler.
"""
from __future__ import annotations

import threading
from datetime import timedelta

from django.db.models import Count, Max, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.attacker_agent import AttackerAgent
from agents.behavior_agent import BehaviorAgent
from agents.data_agent import DataAgent
from agents.resources import get_baseline_store, get_q_agent
from agents.response_agent import ResponseAgent
from agents.risk_agent import RiskAgent
from api import services
from api.health import system_health
from api.models import AgentRun, Analysis, Event, Incident, Simulation
from api.serializers import (AgentRunSerializer, AnalysisDetailSerializer, AnalysisSerializer,
                             ConfigPatchSerializer, DecisionSerializer, EventSerializer, IncidentDetailSerializer,
                             IncidentSerializer, IngestSerializer, ResponseDecideSerializer, SessionSerializer,
                             SimulateSerializer, SimulationSerializer, StreamSerializer, BehaviorResultSerializer)
from api.stream import stream_worker
from core.config import ConfigError, get_config, set_runtime_llm
from core.errors import error_response
from core.logs import ring_buffer


def _limit_offset(request, default: int | None = None, maximum: int = 500) -> tuple[int, int]:
    default = default or get_config().api.page_size
    try:
        limit = max(1, min(int(request.query_params.get("limit", default)), maximum))
        offset = max(0, int(request.query_params.get("offset", 0)))
    except ValueError:
        limit, offset = default, 0
    return limit, offset


def _page(qs, request, serializer_cls, **kwargs) -> Response:
    limit, offset = _limit_offset(request, **kwargs)
    total = qs.count()
    data = serializer_cls(qs[offset:offset + limit], many=True).data
    return Response({"count": total, "limit": limit, "offset": offset, "results": data})


def _service_error(exc: services.ServiceError) -> Response:
    return error_response(exc.code, str(exc), exc.status)


def _bool(value) -> bool | None:
    if value is None:
        return None
    return str(value).lower() in ("1", "true", "yes")


# ── index ──────────────────────────────────────────────────────────────────
class ApiIndexView(APIView):
    public = True

    def get(self, request):
        return Response({
            "name": get_config().app.name, "version": "2.0.0",
            "endpoints": [
                "GET  /api/v1/system/health/", "GET  /api/v1/system/logs/", "GET|POST /api/v1/system/stream/",
                "GET  /api/v1/stats/overview/", "GET  /api/v1/events/", "GET  /api/v1/events/live/",
                "POST /api/v1/events/ingest/", "GET  /api/v1/analyses/", "GET  /api/v1/analyses/<id>/",
                "POST /api/v1/behavior/analyze/", "GET  /api/v1/behavior/users/",
                "GET  /api/v1/behavior/users/<user_id>/", "POST /api/v1/risk/analyze/",
                "POST /api/v1/response/decide/", "GET  /api/v1/response/policy/", "GET  /api/v1/agents/",
                "GET  /api/v1/agents/<name>/", "GET  /api/v1/attacks/", "POST /api/v1/attacks/simulate/",
                "GET  /api/v1/incidents/", "GET  /api/v1/incidents/<id>/", "POST /api/v1/incidents/<id>/decision/",
                "GET  /api/v1/ml/evaluation/", "GET|PATCH /api/v1/config/",
            ],
        })


# ── system ─────────────────────────────────────────────────────────────────
class PingView(APIView):
    """Liveness probe (no auth, no dependencies) — used by Docker health checks."""
    public = True

    def get(self, request):
        return Response({"status": "ok", "time": timezone.now().isoformat()})


class HealthView(APIView):
    def get(self, request):
        return Response(system_health())


class LogsView(APIView):
    def get(self, request):
        try:
            after = int(request.query_params.get("after", 0))
        except ValueError:
            after = 0
        limit, _ = _limit_offset(request, default=200, maximum=1000)
        records = ring_buffer.records(level=request.query_params.get("level"),
                                      logger_prefix=request.query_params.get("logger"), after_id=after, limit=limit)
        return Response({"results": records})


class StreamView(APIView):
    throttle_scope = "ingest"

    def get(self, request):
        return Response(stream_worker.status())

    def post(self, request):
        s = StreamSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        cfg = get_config().stream
        if s.validated_data["action"] == "start":
            stream_worker.start(s.validated_data["source"],
                                s.validated_data.get("interval_seconds", cfg.interval_seconds),
                                s.validated_data.get("batch_size", cfg.batch_size))
        else:
            threading.Thread(target=stream_worker.stop, daemon=True).start()
        return Response(stream_worker.status())


class OverviewView(APIView):
    def get(self, request):
        try:
            hours = max(1, min(int(request.query_params.get("hours", 24)), 24 * 7))
        except ValueError:
            hours = 24
        return Response(services.overview(hours))


# ── events / analyses ──────────────────────────────────────────────────────
class EventListView(APIView):
    def get(self, request):
        qs = Event.objects.select_related("analysis")
        p = request.query_params
        if p.get("severity"):
            qs = qs.filter(severity__in=p["severity"].upper().split(","))
        if p.get("source"):
            qs = qs.filter(source__in=p["source"].split(","))
        if p.get("event_type"):
            qs = qs.filter(event_type__in=p["event_type"].split(","))
        if p.get("user"):
            qs = qs.filter(user_id__icontains=p["user"][:64])
        if p.get("status"):
            qs = qs.filter(analysis__execution__in=p["status"].split(","))
        if _bool(p.get("simulated")) is not None:
            qs = qs.filter(is_simulated=_bool(p.get("simulated")))
        if p.get("since"):
            since = parse_datetime(p["since"])
            if since:
                qs = qs.filter(ingested_at__gte=since)
        if p.get("since_minutes", "").isdigit():
            qs = qs.filter(ingested_at__gte=timezone.now() - timedelta(minutes=int(p["since_minutes"])))
        return _page(qs, request, EventSerializer)


class LiveEventsView(APIView):
    def get(self, request):
        qs = Event.objects.select_related("analysis")
        after = parse_datetime(request.query_params.get("after", "") or "")
        if after:
            qs = qs.filter(ingested_at__gt=after)
        limit, _ = _limit_offset(request, default=50, maximum=200)
        return Response({"results": EventSerializer(qs[:limit], many=True).data,
                         "server_time": timezone.now().isoformat(), "stream": stream_worker.status()})


class IngestView(APIView):
    throttle_scope = "ingest"

    def post(self, request):
        s = IngestSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        try:
            out = services.ingest(d["source"], d["count"], d.get("collectors"), d.get("session"))
        except services.ServiceError as exc:
            return _service_error(exc)
        body = {"analyses": AnalysisSerializer(out["analyses"], many=True).data}
        if "collection" in out:
            body["collection"] = out["collection"]
        return Response(body, status=status.HTTP_201_CREATED)


class AnalysisListView(APIView):
    def get(self, request):
        qs = Analysis.objects.select_related("incident", "simulation")
        p = request.query_params
        if _bool(p.get("flagged")) is not None:
            qs = qs.filter(flagged=_bool(p.get("flagged")))
        if p.get("risk_level"):
            qs = qs.filter(risk_level__in=p["risk_level"].upper().split(","))
        for field in ("kind", "source", "threat_category", "action"):
            if p.get(field):
                qs = qs.filter(**{f"{field}__in": p[field].split(",")})
        if p.get("user"):
            qs = qs.filter(user_id__icontains=p["user"][:64])
        if _bool(p.get("simulated")) is not None:
            qs = qs.filter(is_simulated=_bool(p.get("simulated")))
        return _page(qs, request, AnalysisSerializer)


class AnalysisDetailView(APIView):
    def get(self, request, pk):
        a = get_object_or_404(Analysis.objects.prefetch_related("events", "runs"), pk=pk)
        return Response(AnalysisDetailSerializer(a).data)


# ── individual agents (dry-run, nothing stored) ────────────────────────────
class BehaviorAnalyzeView(APIView):
    def post(self, request):
        s = SessionSerializer(data=request.data.get("session", request.data))
        s.is_valid(raise_exception=True)
        state = {"request": {"source": "manual", "kind": "behavior", "session": dict(s.validated_data),
                             "dry_run": True}, "trace": [], "errors": []}
        state.update(DataAgent()(state))
        if state.get("halted"):
            return error_response("agent_error", "; ".join(state["errors"]), 422)
        out = BehaviorAgent()(state)
        if out.get("halted"):
            return error_response("model_unavailable", "; ".join(out["errors"]), 503)
        return Response({"behavior": out["behavior"], "trace": state["trace"] + out["trace"]})


class RiskAnalyzeView(APIView):
    def post(self, request):
        s = BehaviorResultSerializer(data=request.data.get("behavior", request.data))
        s.is_valid(raise_exception=True)
        out = RiskAgent()({"behavior": dict(s.validated_data), "trace": [], "errors": []})
        if out.get("halted"):
            return error_response("agent_error", "; ".join(out["errors"]), 500)
        return Response({"risk": out["risk"], "trace": out["trace"]})


class ResponseDecideView(APIView):
    def post(self, request):
        s = ResponseDecideSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        risk = dict(s.validated_data["risk"])
        risk.setdefault("decision", {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "ESCALATE"}[risk["risk_level"]])
        out = ResponseAgent()({"behavior": dict(s.validated_data["behavior"]), "risk": risk, "trace": [],
                               "errors": []})
        if out.get("halted"):
            return error_response("agent_error", "; ".join(out["errors"]), 500)
        return Response({"response": out["response"], "trace": out["trace"]})


class ResponsePolicyView(APIView):
    def get(self, request):
        q = get_q_agent()
        return Response({"stats": q.stats(), "table": q.table(limit=100)})


class BehaviorUsersView(APIView):
    def get(self, request):
        qs = Analysis.objects.filter(kind="behavior").exclude(user_id="")
        if request.query_params.get("q"):
            qs = qs.filter(user_id__icontains=request.query_params["q"][:64])
        rows = (qs.values("user_id").annotate(analyses=Count("id"), flagged=Count("id", filter=Q(flagged=True)),
                                              max_score=Max("score"), last_seen=Max("created_at"))
                .order_by("-flagged", "-max_score")[:50])
        return Response({"results": list(rows), "baseline_users": len(get_baseline_store())})


class BehaviorUserView(APIView):
    def get(self, request, user_id):
        b = get_baseline_store().get(user_id[:64])
        recent = Analysis.objects.filter(user_id=user_id[:64], kind="behavior")[:50]
        if b is None and not recent:
            return error_response("not_found", f"No baseline or history for user '{user_id}'.", 404)
        history = [{"id": str(a.id), "created_at": a.created_at.isoformat(), "score": a.score,
                    "risk_level": a.risk_level, "flagged": a.flagged, "rules": a.triggered_rules,
                    "dimension_scores": a.details.get("behavior", {}).get("dimension_scores", {})}
                   for a in recent]
        return Response({"user_id": user_id, "baseline": b.summary() if b else None, "history": history})


# ── agents ─────────────────────────────────────────────────────────────────
class AgentListView(APIView):
    def get(self, request):
        return Response({"results": services.agents_status()})


class AgentDetailView(APIView):
    def get(self, request, name):
        agents = {a["name"]: a for a in services.agents_status()}
        if name not in agents:
            return error_response("not_found", f"Unknown agent '{name}'.", 404)
        runs = AgentRun.objects.filter(agent=name)[:50]
        return Response({**agents[name], "recent_runs": AgentRunSerializer(runs, many=True).data})


# ── attack simulation ──────────────────────────────────────────────────────
class AttackListView(APIView):
    def get(self, request):
        sims = Simulation.objects.prefetch_related("analyses")
        limit, _ = _limit_offset(request, default=25, maximum=200)
        outcomes = dict(Simulation.objects.values_list("status").annotate(n=Count("id")))
        return Response({"scenarios": AttackerAgent().catalogue(), "outcomes": outcomes,
                         "simulations": SimulationSerializer(sims[:limit], many=True).data})


class AttackSimulateView(APIView):
    throttle_scope = "simulate"

    def post(self, request):
        s = SimulateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        try:
            sim = services.simulate(d.get("scenario_id") or None, d.get("target_user") or None, d.get("seed"))
        except services.ServiceError as exc:
            return _service_error(exc)
        return Response(SimulationSerializer(sim).data, status=status.HTTP_201_CREATED)


# ── incidents ──────────────────────────────────────────────────────────────
class IncidentListView(APIView):
    def get(self, request):
        qs = Incident.objects.select_related("analysis", "analysis__incident")
        if request.query_params.get("status"):
            qs = qs.filter(status__in=request.query_params["status"].split(","))
        if request.query_params.get("severity"):
            qs = qs.filter(severity__in=request.query_params["severity"].upper().split(","))
        return _page(qs, request, IncidentSerializer)


class IncidentDetailView(APIView):
    def get(self, request, pk):
        inc = get_object_or_404(Incident.objects.select_related("analysis"), pk=pk)
        return Response(IncidentDetailSerializer(inc).data)


class IncidentDecisionView(APIView):
    def post(self, request, pk):
        s = DecisionSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            inc = services.decide_incident(pk, s.validated_data["decision"], s.validated_data["note"],
                                           s.validated_data["analyst"])
        except services.ServiceError as exc:
            return _service_error(exc)
        return Response(IncidentSerializer(inc).data)


# ── ML evaluation ──────────────────────────────────────────────────────────
_eval_cache: dict = {}


class EvaluationView(APIView):
    def get(self, request):
        if "result" not in _eval_cache or _bool(request.query_params.get("refresh")):
            from ml.evaluation import evaluate

            try:
                _eval_cache["result"] = {**evaluate(), "computed_at": timezone.now().isoformat()}
            except FileNotFoundError as exc:
                return error_response("dataset_missing", str(exc), 503)
        return Response(_eval_cache["result"])


# ── configuration ──────────────────────────────────────────────────────────
class ConfigView(APIView):
    def get(self, request):
        return Response(get_config().public_dict())

    def patch(self, request):
        s = ConfigPatchSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        try:
            cfg = set_runtime_llm(s.validated_data.get("llm_provider"), s.validated_data.get("llm_model"))
        except ConfigError as exc:
            return error_response("validation_error", str(exc), 400)
        from api import health

        health._cache.clear()
        return Response({"llm": cfg.public_dict()["llm"],
                         "note": "Runtime change only — edit config.yaml or .env to make it permanent."})
