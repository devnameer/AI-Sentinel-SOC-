"""Agents: initialisation, pipeline wiring, LLM bounds/fallbacks, honest simulations."""
import pytest

from agents.attacker_agent import SCENARIOS, AttackerAgent
from agents.behavior_agent import BehaviorAgent
from agents.data_agent import DataAgent, aggregate_session
from agents.pipeline import build_graph, run_pipeline
from agents.response_agent import ResponseAgent
from agents.risk_agent import RiskAgent
from core.config import get_config
from core.llm import LLMResult

pytestmark = pytest.mark.django_db


class StubLLM:
    """Programmable LLM used to test agent behaviour around LLM output."""

    def __init__(self, json_reply=None, text="stub explanation", ok=True):
        self.json_reply, self.text, self.ok, self.calls = json_reply, text, ok, 0
        self.enabled = True

    def chat(self, messages, **kw):
        self.calls += 1
        return LLMResult(self.ok, text=self.text if self.ok else "", provider="stub", model="stub",
                         error="" if self.ok else "provider offline")

    def chat_json(self, messages, **kw):
        self.calls += 1
        res = LLMResult(self.ok, provider="stub", model="stub", error="" if self.ok else "provider offline")
        return (self.json_reply if self.ok else None), res


def test_all_agents_initialise():
    for cls in (DataAgent, BehaviorAgent, RiskAgent, ResponseAgent, AttackerAgent):
        agent = cls()
        assert agent.enabled and agent.name


def test_pipeline_on_replay_session():
    from ml.datasets import get_replay_dataset

    session = get_replay_dataset().next_sessions(1)[0]
    truth = session.pop("ground_truth_insider")
    state = run_pipeline({"source": "replay", "session": session, "ground_truth": truth})
    assert not state["errors"]
    assert [t["agent"] for t in state["trace"]] == ["data_agent", "behavior_agent", "risk_agent", "response_agent"]
    assert state["risk"]["risk_level"] in ("LOW", "MEDIUM", "HIGH")
    assert state["response"]["action"] in ("ALLOW", "MONITOR", "ESCALATE", "BLOCK")


@pytest.mark.parametrize("scenario_id", list(SCENARIOS))
def test_every_scenario_runs_through_pipeline(scenario_id):
    req = AttackerAgent(seed=7).build(scenario_id)
    assert req["ground_truth"] == SCENARIOS[scenario_id].malicious
    assert all(e["metadata"]["is_simulated"] for e in req["events"])
    state = run_pipeline(req)
    assert not state["errors"], state["errors"]
    assert state["behavior"]["kind"] == SCENARIOS[scenario_id].kind


def test_detection_is_real_not_forced():
    """The original code forced every simulated attack to 0.95. Now a benign simulation stays benign."""
    state = run_pipeline(AttackerAgent(seed=3).build("benign_workday"))
    assert state["behavior"]["flagged"] is False and state["risk"]["risk_level"] == "LOW"
    attack = run_pipeline(AttackerAgent(seed=3).build("usb_exfil_wikileaks"))
    assert attack["behavior"]["flagged"] and attack["behavior"]["score"] > state["behavior"]["score"]


def test_simulations_never_change_real_baselines():
    from agents.resources import get_baseline_store

    req = AttackerAgent(seed=5).build("usb_exfil_wikileaks", target_user="AAM0658")
    before = get_baseline_store().get("AAM0658").observation_days
    state = run_pipeline(req)
    assert state["behavior"]["baseline_update"] == "skipped (simulation)"
    assert get_baseline_store().get("AAM0658").observation_days == before


def test_aggregation_builds_session_from_events():
    req = AttackerAgent(seed=1).build("jobhunt_usb_theft", target_user="AAF0535")
    s = aggregate_session("AAF0535", req["events"])
    assert s["visited_jobsearch_domain"] == 1 and s["has_ext_email"] == 1 and s["usb_connected"] == 1
    assert s["file_count"] > 0 and s["pc"]


def test_unknown_user_gets_cold_start_not_random_user():
    state = run_pipeline({"source": "manual", "session": {"user_id": "brand.new", "pc": "LAPTOP-1",
                                                          "hour_of_day": 10, "file_count": 3}})
    assert state["session"]["user_id"] == "brand.new"
    assert state["behavior"]["cold_start"] is True and state["behavior"]["confidence"] == "low"


def test_risk_agent_clamps_llm_adjustment():
    stub = StubLLM(json_reply={"risk_adjustment": 0.95, "risk_factors": ["claims huge risk"],
                               "mitigating_factors": [], "reasoning": "trust me"})
    behavior = {"score": 0.3, "flagged": True, "kind": "behavior", "user_id": "u1", "triggered_rules": [],
                "threat_category": "anomalous_behavior", "confidence": "high", "cold_start": False}
    out = RiskAgent(llm=stub)({"behavior": behavior, "trace": [], "errors": []})
    bound = get_config().agents.risk_agent.max_llm_adjustment
    assert out["risk"]["llm_adjustment"] == pytest.approx(bound)
    assert out["risk"]["risk_score"] == pytest.approx(0.3 + bound)
    assert "clamped" in out["risk"]["reasoning"]


def test_agents_fall_back_when_llm_is_down():
    down = StubLLM(ok=False)
    graph = build_graph(behavior=BehaviorAgent(llm=down), risk=RiskAgent(llm=down), response=ResponseAgent(llm=down))
    state = run_pipeline(AttackerAgent(seed=2).build("usb_exfil_wikileaks"), graph=graph)
    assert not state["errors"]
    assert state["behavior"]["explanation_source"] == "template" and state["behavior"]["explanation"]
    assert state["risk"]["method"] == "policy" and state["risk"]["llm_adjustment"] == 0
    assert state["response"]["summary_source"] == "template" and state["response"]["playbook"]
    assert down.calls >= 2


def test_llm_not_called_for_normal_sessions():
    stub = StubLLM(json_reply={"risk_adjustment": 0})
    graph = build_graph(behavior=BehaviorAgent(llm=stub), risk=RiskAgent(llm=stub), response=ResponseAgent(llm=stub))
    state = run_pipeline(AttackerAgent(seed=4).build("benign_workday"), graph=graph)
    assert state["behavior"]["flagged"] is False and stub.calls == 0


def test_high_risk_response_requires_approval_and_respects_floor():
    behavior = {"score": 0.95, "kind": "behavior", "triggered_rules": ["usb_first_time"], "cold_start": False,
                "threat_category": "data_exfiltration", "user_id": "u", "device_id": "d", "flagged": True}
    risk = {"risk_score": 0.95, "risk_level": "HIGH", "decision": "ESCALATE", "recommended_action": "x",
            "risk_factors": [], "mitigating_factors": []}
    out = ResponseAgent(llm=StubLLM(ok=False))({"behavior": behavior, "risk": risk, "trace": [], "errors": []})
    assert out["response"]["execution"] == "awaiting_approval"
    assert out["response"]["action"] in ("ESCALATE", "BLOCK")


def test_halted_pipeline_reports_error():
    state = run_pipeline({"source": "manual", "kind": "behavior"})
    assert state["halted"] and "neither a session nor events" in state["errors"][0]
    assert [t["agent"] for t in state["trace"]] == ["data_agent"]


def test_attacker_llm_planning_is_constrained(settings):
    cfg = get_config()
    cfg.llm.features.attack_planning = True
    try:
        sid, meta = AttackerAgent(llm=StubLLM(json_reply={"scenario_id": "rm -rf /"})).plan([])
        assert sid in SCENARIOS and meta["method"] == "least_tested"
        sid, meta = AttackerAgent(llm=StubLLM(json_reply={"scenario_id": "port_scan", "reasoning": "r"})).plan([])
        assert sid == "port_scan" and meta["method"] == "llm"
    finally:
        cfg.llm.features.attack_planning = False
