"""ML: features, model loading safeguards, scoring modes, network rules, baselines, Q-learning."""
import json
from pathlib import Path

import numpy as np
import pytest

from ml.baselines import BaselineStore
from ml.behavior_model import BehaviorModel, ModelUnavailable
from ml.features import NETWORK_FEATURE_NAMES, behavior_features, network_features, normalize_session
from ml.network_model import network_rules
from ml.q_learning import ACTIONS, QLearningAgent, apply_guardrails, encode_state, reward_from_ground_truth

NORMAL = {"user_id": "AAM0658", "pc": "PC-9923", "hour_of_day": 0, "duration_minutes": 400, "file_count": 0}
EXFIL = {**NORMAL, "hour_of_day": 13, "usb_connected": 1, "usb_first_time": 1, "visited_exfil_domain": 1,
         "file_count": 60, "max_sensitivity": 2, "is_outside_hours": 0}


@pytest.fixture
def store(cfg, tmp_path):
    return BaselineStore(tmp_path / "b.sqlite", seed_path=cfg.path(cfg.ml.behavior.baselines_seed_path))


def test_feature_vector_matches_model_columns(cfg, store):
    cols = json.loads(cfg.path(cfg.ml.behavior.feature_columns_path).read_text())
    feats = behavior_features(normalize_session(NORMAL), store.get("AAM0658"))
    assert list(feats) == cols and len(cols) == 18


def test_model_scores_attack_above_normal(store):
    model = BehaviorModel()
    b = store.get("AAM0658")
    normal = model.score(normalize_session(NORMAL), b)
    attack = model.score(normalize_session(EXFIL), b)
    assert 0 <= normal.score < attack.score <= 1
    assert attack.flagged and not normal.flagged
    assert {"usb_first_time", "exfil_domain_visited"} <= set(attack.triggered_rules)


def test_isolation_forest_only_mode(cfg, store):
    cfg_if = cfg.model_copy(deep=True)
    cfg_if.ml.behavior.scoring_mode = "isolation_forest"
    s = BehaviorModel(cfg_if).score(normalize_session(EXFIL), store.get("AAM0658"))
    assert s.score == pytest.approx(s.if_score)


def test_missing_model_file_is_reported_not_crashing(cfg, store):
    broken = cfg.model_copy(deep=True)
    broken.ml.behavior.model_path = "models/does_not_exist.joblib"
    model = BehaviorModel(broken)
    st = model.status()
    assert st["status"] == "unavailable" and "missing" in st["error"]
    with pytest.raises(ModelUnavailable):
        model.score(normalize_session(NORMAL), store.get("AAM0658"))


def test_vectorised_scores_match_single(store):
    model = BehaviorModel()
    b = store.get("AAM0658")
    rows = [behavior_features(normalize_session(s), b) for s in (NORMAL, EXFIL)]
    batch = model.if_scores(rows)
    assert batch[0] == pytest.approx(model.if_score(rows[0]))
    assert batch[1] == pytest.approx(model.if_score(rows[1]))


def test_network_features_shape():
    v = network_features([{"protocol": "udp", "dst_port": 53, "bytes_sent": 60, "bytes_received": 3000,
                           "timestamp": "2026-01-01T00:00:00"}])
    assert v.shape == (len(NETWORK_FEATURE_NAMES),) == (34,) and np.isfinite(v).all()


def _conn(i, dport, proto="TCP", sent=60, recv=0, dst="10.0.0.5"):
    return {"src_ip": "10.0.1.9", "dst_ip": dst, "src_port": 40000 + i, "dst_port": dport, "protocol": proto,
            "bytes_sent": sent, "bytes_received": recv, "timestamp": f"2026-01-01T00:00:{i % 60:02d}"}


def test_network_rules_detect_patterns():
    scan = [_conn(i, p) for i, p in enumerate(range(20, 40))]
    assert network_rules(scan)[2] == "Port_Scan"
    flood = [_conn(i, 443) for i in range(25)]
    assert network_rules(flood)[2] == "SYN_Flood"
    amp = [_conn(i, 53, "UDP", 70, 3500, dst=f"198.51.100.{i % 3}") for i in range(25)]
    assert network_rules(amp)[2] == "DrDoS_DNS"
    web = [_conn(i, 443, "TCP", 800, 40000, dst=f"142.250.0.{i}") for i in range(25)]
    assert network_rules(web)[1] == 0.0  # ordinary HTTPS browsing triggers nothing


def test_cold_start_baseline_for_unknown_user(store):
    assert store.get("new.user") is None
    b = store.get_or_create("new.user")
    assert b.cold_start and b.observation_days == 0 and store.get("new.user") is not None


def test_score_gated_baseline_update(store):
    before = list(store.get("AAM0658").daily_volume_history)
    assert store.update_after_scoring("AAM0658", EXFIL, 0.95, 0.4) == "gated"
    assert store.get("AAM0658").daily_volume_history == before          # attack did not teach the baseline
    assert store.update_after_scoring("AAM0658", NORMAL, 0.05, 0.4) == "full"
    assert store.get("AAM0658").recent_scores[-2:] == [0.95, 0.05]


# ── Q-learning ────────────────────────────────────────────────────────────
def test_state_encoding():
    assert encode_state("HIGH", 0.93, 4, False) == "HIGH|s4|r2|warm"
    assert encode_state("LOW", 0.05, 0, True) == "LOW|s0|r0|cold"


def test_q_update_formula(tmp_path):
    agent = QLearningAgent(tmp_path / "q.json", alpha=0.5, gamma=0.0)
    s = "HIGH|s4|r2|warm"
    agent.update(s, "BLOCK", 1.0)           # 0 + 0.5 * (1 - 0) = 0.5
    agent.update(s, "BLOCK", 1.0)           # 0.5 + 0.5 * (1 - 0.5) = 0.75
    assert agent.q[s]["BLOCK"] == pytest.approx(0.75)
    agent2 = QLearningAgent(tmp_path / "q2.json", alpha=0.5, gamma=0.9)
    agent2.q["next"] = {a: 0.0 for a in ACTIONS}
    agent2.q["next"]["ALLOW"] = 1.0
    agent2.update("s", "MONITOR", 0.0, next_state="next")   # 0.5 * (0 + 0.9 * 1.0) = 0.45
    assert agent2.q["s"]["MONITOR"] == pytest.approx(0.45)


def test_policy_learns_and_persists(tmp_path):
    path = tmp_path / "q.json"
    agent = QLearningAgent(path, alpha=0.3, epsilon=0.0, seed=1)
    s = "HIGH|s4|r3|warm"
    assert agent.recommend(s, "HIGH").source == "rule_fallback"
    for _ in range(30):
        for a in ACTIONS:
            agent.update(s, a, reward_from_ground_truth(a, malicious=True))
    assert agent.recommend(s, "HIGH").action == "BLOCK"
    agent.save()
    reloaded = QLearningAgent(path)
    assert reloaded.recommend(s, "HIGH").action == "BLOCK" and reloaded.updates == 120
    assert json.loads(Path(path).read_text())["format"] == "q_table/v1"  # JSON, not pickle


def test_seed_table_is_read_but_never_written(tmp_path):
    """Analyst feedback must update the runtime copy, never the committed pre-trained table."""
    seed, runtime = tmp_path / "seed.json", tmp_path / "runtime" / "q.json"
    trained = QLearningAgent(seed, alpha=0.5)
    trained.update("HIGH|s4|r3|warm", "BLOCK", 1.0)
    trained.save()
    before = seed.read_text()

    live = QLearningAgent(runtime, alpha=0.5, seed_path=seed)
    assert live.recommend("HIGH|s4|r3|warm", "HIGH").source == "q_table"   # started from the seed
    live.update("HIGH|s4|r3|warm", "BLOCK", -1.0)
    live.save()
    assert runtime.exists() and seed.read_text() == before
    assert QLearningAgent(runtime, seed_path=seed).updates == 2           # runtime copy wins once it exists


def test_guardrails():
    assert apply_guardrails("ALLOW", "HIGH", {"HIGH": "ESCALATE"}, {})[0] == "ESCALATE"
    assert apply_guardrails("BLOCK", "LOW", {}, {"LOW": "MONITOR"})[0] == "MONITOR"
    assert apply_guardrails("BLOCK", "HIGH", {"HIGH": "ESCALATE"}, {}) == ("BLOCK", None)


def test_shipped_q_table_is_trained(cfg):
    data = json.loads(cfg.path("models/rl/q_table.json").read_text())
    assert data["updates"] > 1000 and data["metadata"]["held_out_good_action_rate"] > 0.5


def test_host_snapshot_without_byte_counts_is_not_scored_by_ml():
    """psutil cannot see bytes; unknown must not be treated as zero (that produced false SYN-flood/IF alerts)."""
    from ml.network_model import NetworkModel

    conns = [{"src_ip": "10.0.0.2", "dst_ip": "127.0.0.1" if i % 2 else "160.79.104.10", "src_port": 50000 + i,
              "dst_port": 8000 if i % 2 else 443, "protocol": "TCP", "bytes_sent": None, "bytes_received": None,
              "timestamp": "2026-01-01T00:00:00"} for i in range(24)]
    r = NetworkModel().score(conns)
    assert r["mode"] == "rules_only_no_byte_counts" and r["flagged"] is False and r["if_score"] is None
