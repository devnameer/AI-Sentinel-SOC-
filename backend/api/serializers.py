"""Request validation and response shapes for the v1 API."""
from __future__ import annotations

from rest_framework import serializers

from agents.attacker_agent import SCENARIOS
from api.models import AgentRun, Analysis, Event, Incident, Simulation
from tools.collectors import COLLECTORS

IDENTIFIER = r"^[A-Za-z0-9_.@:\-]{1,64}$"


# ── input ──────────────────────────────────────────────────────────────────
class SessionSerializer(serializers.Serializer):
    user_id = serializers.RegexField(IDENTIFIER)
    pc = serializers.CharField(max_length=128, required=False, allow_blank=True, default="")
    session_start = serializers.DateTimeField(required=False)
    hour_of_day = serializers.IntegerField(min_value=0, max_value=23)
    is_weekend = serializers.IntegerField(min_value=0, max_value=1, default=0)
    is_outside_hours = serializers.IntegerField(min_value=0, max_value=1, default=0)
    duration_minutes = serializers.FloatField(min_value=0, max_value=24 * 60, default=60)
    file_count = serializers.IntegerField(min_value=0, max_value=100_000, default=0)
    max_sensitivity = serializers.IntegerField(min_value=0, max_value=3, default=0)
    usb_connected = serializers.IntegerField(min_value=0, max_value=1, default=0)
    usb_first_time = serializers.IntegerField(min_value=0, max_value=1, default=0)
    email_count = serializers.IntegerField(min_value=0, max_value=10_000, default=0)
    has_ext_email = serializers.IntegerField(min_value=0, max_value=1, default=0)
    visited_exfil_domain = serializers.IntegerField(min_value=0, max_value=1, default=0)
    visited_jobsearch_domain = serializers.IntegerField(min_value=0, max_value=1, default=0)

    def validate(self, data):
        from django.utils import timezone

        ts = data.get("session_start") or timezone.now()
        data["session_start"] = ts.isoformat()
        return data


class IngestSerializer(serializers.Serializer):
    source = serializers.ChoiceField(choices=["replay", "host", "manual"], default="replay")
    count = serializers.IntegerField(min_value=1, max_value=20, default=1)
    collectors = serializers.ListField(child=serializers.ChoiceField(choices=list(COLLECTORS)), required=False,
                                       max_length=len(COLLECTORS))
    session = SessionSerializer(required=False)


class SimulateSerializer(serializers.Serializer):
    scenario_id = serializers.ChoiceField(choices=list(SCENARIOS), required=False, allow_blank=True)
    target_user = serializers.RegexField(IDENTIFIER, required=False, allow_blank=True)
    seed = serializers.IntegerField(required=False, min_value=0, max_value=2**31 - 1)


class DecisionSerializer(serializers.Serializer):
    decision = serializers.ChoiceField(choices=["approve", "deny"])
    note = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")
    analyst = serializers.RegexField(IDENTIFIER, required=False, default="analyst")


class StreamSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=["start", "stop"])
    source = serializers.ChoiceField(choices=["replay", "host"], default="replay")
    interval_seconds = serializers.FloatField(min_value=0.5, max_value=300, required=False)
    batch_size = serializers.IntegerField(min_value=1, max_value=20, required=False)


class ConfigPatchSerializer(serializers.Serializer):
    llm_provider = serializers.ChoiceField(choices=["ollama", "groq", "huggingface", "openai_compatible", "mock",
                                                    "none"], required=False)
    llm_model = serializers.RegexField(r"^[A-Za-z0-9_.:/\-]{1,128}$", required=False)


class BehaviorResultSerializer(serializers.Serializer):
    """Minimal Behavior Agent output accepted by /risk/analyze/ and /response/decide/."""
    score = serializers.FloatField(min_value=0, max_value=1)
    flagged = serializers.BooleanField(required=False)
    kind = serializers.ChoiceField(choices=["behavior", "network"], default="behavior")
    user_id = serializers.CharField(max_length=128, required=False, default="")
    device_id = serializers.CharField(max_length=128, required=False, default="")
    triggered_rules = serializers.ListField(child=serializers.CharField(max_length=64), required=False, default=list)
    threat_category = serializers.CharField(max_length=64, required=False, default="anomalous_behavior")
    mitre_techniques = serializers.ListField(child=serializers.CharField(max_length=16), required=False, default=list)
    confidence = serializers.ChoiceField(choices=["low", "medium", "high"], default="medium")
    cold_start = serializers.BooleanField(default=False)
    verdict = serializers.CharField(max_length=16, required=False, default="")
    explanation = serializers.CharField(max_length=4000, required=False, default="")

    def validate(self, data):
        if "flagged" not in data:
            from core.config import get_config

            data["flagged"] = data["score"] >= get_config().ml.behavior.anomaly_threshold
        return data


class RiskResultSerializer(serializers.Serializer):
    risk_score = serializers.FloatField(min_value=0, max_value=1)
    risk_level = serializers.ChoiceField(choices=["LOW", "MEDIUM", "HIGH"])
    decision = serializers.ChoiceField(choices=["ALLOW", "MONITOR", "ESCALATE", "BLOCK"], required=False)
    recommended_action = serializers.CharField(max_length=500, required=False, default="")
    risk_factors = serializers.ListField(child=serializers.CharField(max_length=200), required=False, default=list)
    mitigating_factors = serializers.ListField(child=serializers.CharField(max_length=200), required=False,
                                               default=list)


class ResponseDecideSerializer(serializers.Serializer):
    behavior = BehaviorResultSerializer()
    risk = RiskResultSerializer()


# ── output ─────────────────────────────────────────────────────────────────
class EventSerializer(serializers.ModelSerializer):
    analysis_id = serializers.UUIDField(source="analysis.id", read_only=True, default=None)

    class Meta:
        model = Event
        fields = ["id", "timestamp", "ingested_at", "source", "event_type", "category", "user_id", "device_id",
                  "resource", "metadata", "is_simulated", "severity", "analysis_id"]


class IncidentBriefSerializer(serializers.ModelSerializer):
    reference = serializers.CharField(read_only=True)

    class Meta:
        model = Incident
        fields = ["id", "reference", "status", "severity", "recommended_action", "final_action"]


class AnalysisSerializer(serializers.ModelSerializer):
    incident = IncidentBriefSerializer(read_only=True)
    simulation_id = serializers.UUIDField(source="simulation.id", read_only=True, default=None)

    class Meta:
        model = Analysis
        fields = ["id", "created_at", "source", "kind", "user_id", "device_id", "score", "flagged", "verdict",
                  "model", "triggered_rules", "threat_category", "mitre_techniques", "explanation",
                  "explanation_source", "risk_score", "risk_level", "decision", "action", "execution",
                  "is_simulated", "ground_truth", "status", "errors", "incident", "simulation_id"]


class AgentRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentRun
        fields = ["id", "agent", "started_at", "duration_ms", "status", "summary", "error", "analysis_id", "details"]


class AnalysisDetailSerializer(AnalysisSerializer):
    events = EventSerializer(many=True, read_only=True)
    runs = AgentRunSerializer(many=True, read_only=True)

    class Meta(AnalysisSerializer.Meta):
        fields = AnalysisSerializer.Meta.fields + ["details", "events", "runs"]


class IncidentSerializer(serializers.ModelSerializer):
    reference = serializers.CharField(read_only=True)
    analysis = AnalysisSerializer(read_only=True)

    class Meta:
        model = Incident
        fields = ["id", "reference", "created_at", "updated_at", "title", "severity", "status",
                  "recommended_action", "final_action", "decided_at", "decided_by", "decision_note",
                  "notification", "analysis"]


class IncidentDetailSerializer(IncidentSerializer):
    analysis = AnalysisDetailSerializer(read_only=True)


class SimulationSerializer(serializers.ModelSerializer):
    analysis = serializers.SerializerMethodField()

    class Meta:
        model = Simulation
        fields = ["id", "created_at", "scenario_id", "name", "kind", "technique", "tactic", "target", "device",
                  "expected_malicious", "status", "planner", "error", "analysis"]

    def get_analysis(self, obj):
        a = obj.analyses.first()
        if a is None:
            return None
        return {"id": str(a.id), "score": a.score, "flagged": a.flagged, "risk_level": a.risk_level,
                "risk_score": a.risk_score, "action": a.action, "execution": a.execution,
                "triggered_rules": a.triggered_rules, "explanation": a.explanation,
                "incident_id": getattr(getattr(a, "incident", None), "id", None)}
