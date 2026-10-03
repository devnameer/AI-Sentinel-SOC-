"""
Database models (SQLite by default, PostgreSQL optional).

Event       raw telemetry shown in Live Events
Analysis    one pipeline run (Data → Behavior → Risk → Response) for a session / network window
Incident    an Analysis that needs analyst attention (MEDIUM/HIGH) — APPROVE / DENY lives here
Simulation  one Attacker Agent run with its ground truth and detection outcome
AgentRun    per-agent telemetry (latency, status, errors) → Agents page, nothing is invented
"""
from __future__ import annotations

import uuid

from django.db import models

RISK_LEVELS = [("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High")]
ACTIONS = [("ALLOW", "Allow"), ("MONITOR", "Monitor"), ("ESCALATE", "Escalate"), ("BLOCK", "Block")]


class Simulation(models.Model):
    STATUS = [("running", "Running"), ("detected", "Detected"), ("missed", "Missed"),
              ("correctly_ignored", "Correctly ignored"), ("false_positive", "False positive"),
              ("error", "Error")]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    scenario_id = models.CharField(max_length=64, db_index=True)
    name = models.CharField(max_length=128)
    kind = models.CharField(max_length=16)
    technique = models.CharField(max_length=32, blank=True)
    tactic = models.CharField(max_length=64, blank=True)
    target = models.CharField(max_length=128)
    device = models.CharField(max_length=128, blank=True)
    expected_malicious = models.BooleanField(default=True)
    status = models.CharField(max_length=24, choices=STATUS, default="running")
    planner = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]


class Analysis(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.CharField(max_length=16, db_index=True)      # replay | host | attacker | manual
    kind = models.CharField(max_length=16, db_index=True)        # behavior | network
    user_id = models.CharField(max_length=128, db_index=True, blank=True)
    device_id = models.CharField(max_length=128, blank=True)
    # Behavior Agent
    score = models.FloatField(null=True)
    flagged = models.BooleanField(default=False, db_index=True)
    verdict = models.CharField(max_length=16, blank=True)
    model = models.CharField(max_length=64, blank=True)
    triggered_rules = models.JSONField(default=list, blank=True)
    threat_category = models.CharField(max_length=64, blank=True, db_index=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    explanation = models.TextField(blank=True)
    explanation_source = models.CharField(max_length=16, blank=True)   # llm | template
    # Risk Agent
    risk_score = models.FloatField(null=True)
    risk_level = models.CharField(max_length=8, choices=RISK_LEVELS, blank=True, db_index=True)
    decision = models.CharField(max_length=16, choices=ACTIONS, blank=True)
    # Response Agent
    action = models.CharField(max_length=16, choices=ACTIONS, blank=True)
    execution = models.CharField(max_length=24, blank=True)             # logged | awaiting_approval | auto_executed
    # Ground truth (simulations / labelled replay) — for evaluation only, never fed to the models
    is_simulated = models.BooleanField(default=False, db_index=True)
    ground_truth = models.BooleanField(null=True)
    simulation = models.ForeignKey(Simulation, null=True, blank=True, on_delete=models.SET_NULL,
                                   related_name="analyses")
    status = models.CharField(max_length=16, default="ok")              # ok | error
    errors = models.JSONField(default=list, blank=True)
    details = models.JSONField(default=dict, blank=True)                # full agent outputs

    class Meta:
        ordering = ["-created_at"]


class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(db_index=True)          # when the activity happened
    ingested_at = models.DateTimeField(auto_now_add=True, db_index=True)
    source = models.CharField(max_length=32, db_index=True)
    event_type = models.CharField(max_length=32, db_index=True)
    category = models.CharField(max_length=32, blank=True)
    user_id = models.CharField(max_length=128, blank=True, db_index=True)
    device_id = models.CharField(max_length=128, blank=True)
    resource = models.CharField(max_length=512, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    is_simulated = models.BooleanField(default=False, db_index=True)
    severity = models.CharField(max_length=8, blank=True, db_index=True)   # copied from the analysis risk level
    analysis = models.ForeignKey(Analysis, null=True, blank=True, on_delete=models.CASCADE, related_name="events")

    class Meta:
        ordering = ["-ingested_at", "-timestamp"]


class Incident(models.Model):
    STATUS = [("awaiting_approval", "Awaiting approval"), ("auto_executed", "Auto-executed"),
              ("approved", "Approved"), ("denied", "Denied"), ("resolved", "Resolved")]
    analysis = models.OneToOneField(Analysis, on_delete=models.CASCADE, related_name="incident")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=8, choices=RISK_LEVELS)
    status = models.CharField(max_length=24, choices=STATUS, db_index=True)
    recommended_action = models.CharField(max_length=16, choices=ACTIONS)
    final_action = models.CharField(max_length=16, choices=ACTIONS, blank=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.CharField(max_length=64, blank=True)
    decision_note = models.TextField(blank=True)
    notification = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def reference(self) -> str:
        return f"INC-{self.pk:05d}"


class AgentRun(models.Model):
    agent = models.CharField(max_length=32, db_index=True)
    started_at = models.DateTimeField(db_index=True)
    duration_ms = models.FloatField(default=0)
    status = models.CharField(max_length=16)                  # ok | error | skipped
    summary = models.CharField(max_length=300, blank=True)
    error = models.TextField(blank=True)
    analysis = models.ForeignKey(Analysis, null=True, blank=True, on_delete=models.CASCADE, related_name="runs")
    details = models.JSONField(default=dict, blank=True)      # tool calls, LLM metadata

    class Meta:
        ordering = ["-started_at"]
