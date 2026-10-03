"""REST API: endpoints, validation, error shape, auth, human-in-the-loop, RL feedback."""
import json

import pytest

from api.models import AgentRun, Analysis, Event, Incident, Simulation
from core.config import get_config

pytestmark = pytest.mark.django_db


def test_ping_and_index_are_public(api):
    assert api.get("/system/ping/").json()["status"] == "ok"
    assert "endpoints" in api.get("/").json()


def test_health_reports_components(api):
    body = api.get("/system/health/").json()
    comps = body["components"]
    assert comps["database"]["status"] == "online"
    assert comps["behavior_model"]["status"] == "loaded"
    assert comps["llm"]["primary"]["provider"] == "mock"
    assert comps["retrieval"]["status"] == "ready"
    assert any("authentication is disabled" in w for w in body["warnings"])


def test_replay_ingest_persists_everything(api):
    r = api.post("/events/ingest/", {"source": "replay", "count": 3})
    assert r.status_code == 201
    analyses = r.json()["analyses"]
    assert len(analyses) == 3 and all(a["status"] == "ok" for a in analyses)
    assert Analysis.objects.count() == 3 and Event.objects.count() >= 3
    assert AgentRun.objects.filter(agent="behavior_agent").count() == 3
    detail = api.get(f"/analyses/{analyses[0]['id']}/").json()
    assert detail["events"] and len(detail["runs"]) == 4 and "behavior" in detail["details"]


def test_manual_session_validation(api):
    bad = api.post("/events/ingest/", {"source": "manual", "session": {"user_id": "x", "hour_of_day": 99}})
    assert bad.status_code == 400
    err = bad.json()["error"]
    assert err["code"] == "validation_error" and "hour_of_day" in json.dumps(err["details"])
    ok = api.post("/events/ingest/", {"source": "manual", "session": {"user_id": "AAM0658", "hour_of_day": 2,
                                                                     "usb_connected": 1, "usb_first_time": 1}})
    assert ok.status_code == 201


def test_simulation_creates_incident_and_approval_trains_rl(api):
    sim = api.post("/attacks/simulate/", {"scenario_id": "usb_exfil_wikileaks", "seed": 11})
    assert sim.status_code == 201
    body = sim.json()
    assert body["status"] == "detected" and body["expected_malicious"] is True
    incident_id = body["analysis"]["incident_id"]
    inc = api.get(f"/incidents/{incident_id}/").json()
    assert inc["status"] == "awaiting_approval" and inc["analysis"]["is_simulated"] is True

    from agents.resources import get_q_agent
    before = get_q_agent().updates
    approved = api.post(f"/incidents/{incident_id}/decision/", {"decision": "approve", "note": "confirmed"})
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert approved.json()["final_action"] == inc["recommended_action"]
    assert get_q_agent().updates == before + 1          # analyst feedback became an RL reward
    again = api.post(f"/incidents/{incident_id}/decision/", {"decision": "deny"})
    assert again.status_code == 409 and again.json()["error"]["code"] == "conflict"


def test_deny_records_false_positive(api):
    sim = api.post("/attacks/simulate/", {"scenario_id": "syn_flood", "seed": 2}).json()
    inc_id = sim["analysis"]["incident_id"]
    r = api.post(f"/incidents/{inc_id}/decision/", {"decision": "deny", "note": "load test"})
    assert r.json()["status"] == "denied" and r.json()["final_action"] == "MONITOR"


def test_benign_simulation_is_not_an_incident(api):
    body = api.post("/attacks/simulate/", {"scenario_id": "benign_workday", "seed": 5}).json()
    assert body["status"] == "correctly_ignored" and body["analysis"]["incident_id"] is None


def test_planner_picks_a_scenario_when_none_given(api):
    body = api.post("/attacks/simulate/", {}).json()
    assert body["scenario_id"] and body["planner"]["method"] in ("least_tested", "llm")


def test_attack_catalogue_and_history(api):
    api.post("/attacks/simulate/", {"scenario_id": "port_scan", "seed": 1})
    body = api.get("/attacks/").json()
    assert len(body["scenarios"]) == 8 and body["simulations"][0]["scenario_id"] == "port_scan"
    assert Simulation.objects.count() == 1


def test_event_filters_and_live_feed(api):
    api.post("/events/ingest/", {"source": "replay", "count": 2})
    api.post("/attacks/simulate/", {"scenario_id": "dns_amplification", "seed": 1})
    sim_events = api.get("/events/", simulated="true").json()
    assert sim_events["count"] > 0 and all(e["is_simulated"] for e in sim_events["results"])
    high = api.get("/events/", severity="high").json()
    assert all(e["severity"] == "HIGH" for e in high["results"])
    live = api.get("/events/live/", limit=5).json()
    assert len(live["results"]) <= 5 and "server_time" in live


def test_individual_agent_endpoints(api):
    b = api.post("/behavior/analyze/", {"user_id": "AAM0658", "hour_of_day": 14, "usb_connected": 1,
                                        "usb_first_time": 1, "visited_exfil_domain": 1, "file_count": 50}).json()
    assert b["behavior"]["flagged"] and b["behavior"]["baseline_update"] == "skipped (dry run)"
    r = api.post("/risk/analyze/", {"behavior": {"score": 0.82, "triggered_rules": ["usb_first_time"]}}).json()
    assert r["risk"]["risk_level"] == "HIGH"
    d = api.post("/response/decide/", {"behavior": {"score": 0.1}, "risk": {"risk_score": 0.1, "risk_level": "LOW"}})
    assert d.json()["response"]["execution"] == "logged"
    assert api.get("/response/policy/").json()["stats"]["trained_states"] > 0


def test_overview_and_agents(api):
    api.post("/events/ingest/", {"source": "replay", "count": 2})
    api.post("/attacks/simulate/", {"scenario_id": "keylogger_impersonation", "seed": 3})
    ov = api.get("/stats/overview/", hours=24).json()
    assert ov["totals"]["analyses"] == 3 and len(ov["timeline"]) == 24
    assert sum(ov["risk_distribution"].values()) == 3
    agents = {a["name"]: a for a in api.get("/agents/").json()["results"]}
    assert agents["behavior_agent"]["processed"] == 3 and agents["attacker_agent"]["processed"] == 1
    detail = api.get("/agents/risk_agent/").json()
    assert detail["recent_runs"] and api.get("/agents/nope/").status_code == 404


def test_behavior_user_view(api):
    api.post("/events/ingest/", {"source": "manual", "session": {"user_id": "AAM0658", "hour_of_day": 3}})
    body = api.get("/behavior/users/AAM0658/").json()
    assert body["baseline"]["user_id"] == "AAM0658" and body["history"]
    assert api.get("/behavior/users/does-not-exist/").status_code == 404


def test_config_endpoint_hides_secrets_and_switches_provider(api):
    cfg = api.get("/config/").json()
    assert "secrets" not in cfg and "secrets_configured" in cfg
    r = api.patch("/config/", {"llm_provider": "none"})
    assert r.status_code == 200 and r.json()["llm"]["provider"] == "none"
    assert api.patch("/config/", {"llm_provider": "chatgpt"}).status_code == 400
    api.patch("/config/", {"llm_provider": "mock"})


def test_logs_endpoint(api):
    api.post("/events/ingest/", {"source": "bogus"})
    logs = api.get("/system/logs/", level="WARNING").json()["results"]
    assert any(r["level"] == "WARNING" for r in logs)


def test_stream_start_stop(api):
    from api.stream import stream_worker

    started = api.post("/system/stream/", {"action": "start", "interval_seconds": 60, "batch_size": 1}).json()
    assert started["status"] == "running"
    api.post("/system/stream/", {"action": "stop"})   # the view stops the worker in a background thread
    # Wait for the in-flight batch to finish so it cannot write to the test database while later
    # tests run (SQLite's shared in-memory test DB raises "table is locked" instead of waiting).
    stream_worker.stop()
    assert stream_worker.status()["status"] == "stopped"


def test_token_auth_when_configured(api):
    cfg = get_config()
    cfg.secrets.soc_api_token = "s3cret-token"
    try:
        assert api.get("/stats/overview/").status_code in (401, 403)
        assert api.get("/system/ping/").status_code == 200                   # liveness stays public
        from django.test import Client

        c = Client()
        good = c.get("/api/v1/stats/overview/", HTTP_AUTHORIZATION="Bearer s3cret-token")
        bad = c.get("/api/v1/stats/overview/", HTTP_AUTHORIZATION="Bearer wrong")
        assert good.status_code == 200 and bad.status_code == 401
        assert bad.json()["error"]["code"] == "authentication_failed"
    finally:
        cfg.secrets.soc_api_token = ""


def test_unknown_routes_and_ids(api):
    assert api.get("/incidents/99999/").status_code == 404
    assert api.post("/incidents/99999/decision/", {"decision": "approve"}).status_code == 404
    assert Incident.objects.count() == 0


def test_end_to_end_smoke(api):
    """Backend → Agents → ML → (mock) LLM → Response → human approval, through the HTTP API only."""
    health = api.get("/system/health/").json()
    assert health["components"]["behavior_model"]["status"] == "loaded"
    resp = api.post("/attacks/simulate/", {"scenario_id": "jobhunt_usb_theft", "seed": 8})
    sim = resp.json()
    assert resp.status_code == 201, sim
    analysis = api.get(f"/analyses/{sim['analysis']['id']}/").json()
    agents_run = [r["agent"] for r in analysis["runs"]]
    assert sorted(agents_run) == ["behavior_agent", "data_agent", "response_agent", "risk_agent"]
    assert analysis["explanation_source"] == "llm"                       # mock provider answered
    assert analysis["details"]["risk"]["method"] == "policy+llm"
    if analysis["incident"]:
        r = api.post(f"/incidents/{analysis['incident']['id']}/decision/", {"decision": "approve"})
        assert r.json()["status"] == "approved"
