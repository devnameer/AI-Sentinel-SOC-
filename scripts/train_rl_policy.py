#!/usr/bin/env python
"""
Pre-train the Response Agent's Q-table from GROUND TRUTH (not from its own decisions).

Episodes come from two labelled sources:
  1. Attacker-Agent simulations of every scenario (label = scenario is malicious or the benign control)
  2. CERT r4.2 replay sessions (label = inside an insider's malicious window; approximate)

For each episode: behaviour model score → risk level (policy thresholds, no LLM)
→ state → ε-greedy action → reward from ground truth → Q-learning update.
A held-out split measures how often the greedy policy picks a "good" action.

Usage (from the repository root):
    python scripts/train_rl_policy.py                    # writes models/rl/q_table.json
    python scripts/train_rl_policy.py --episodes 50000 --output /tmp/q.json
"""
from __future__ import annotations

import argparse
import random
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from core.config import get_config  # noqa: E402
from ml.baselines import BaselineStore  # noqa: E402
from ml.behavior_model import BehaviorModel  # noqa: E402
from ml.datasets import add_insider_labels, load_sessions, row_to_session  # noqa: E402
from ml.network_model import NetworkModel  # noqa: E402
from ml.q_learning import ACTIONS, QLearningAgent, encode_state, reward_from_ground_truth  # noqa: E402


def classify(score: float, t: dict) -> str:
    return "LOW" if score < t["low_max"] else "MEDIUM" if score <= t["medium_max"] else "HIGH"


def build_samples(cfg, n_sim: int, n_benign: int, seed: int):
    """Return a list of (state, risk_level, malicious) tuples."""
    import agents.resources as res
    from agents.attacker_agent import SCENARIOS, AttackerAgent
    from agents.data_agent import aggregate_session, connections_from_events

    tmp = Path(tempfile.mkdtemp()) / "baselines.sqlite"
    store = BaselineStore(tmp, seed_path=cfg.path(cfg.ml.behavior.baselines_seed_path))
    res._store = store  # the attacker agent reads baselines from here — never the runtime copy
    model, net = BehaviorModel(cfg), NetworkModel(cfg)
    t = cfg.risk.thresholds
    samples = []

    attacker = AttackerAgent(seed=seed)
    for sid, sc in SCENARIOS.items():
        for _ in range(n_sim):
            req = attacker.build(sid)
            if sc.kind == "network":
                r = net.score(connections_from_events(req["events"]))
                score, rules, cold = r["score"], r["triggered_rules"], False
            else:
                s = aggregate_session(req["events"][0]["user_id"], req["events"])
                b = store.get_or_create(s["user_id"])
                out = model.score(s, b)
                score, rules, cold = out.score, out.triggered_rules, b.cold_start
            lvl = classify(score, t)
            samples.append((encode_state(lvl, score, len(rules), cold), lvl, sc.malicious))

    df = add_insider_labels(load_sessions(cfg.path(cfg.data.replay_dataset_path)), cfg.path(cfg.data.insiders_path))
    pos = df[df.insider == 1]
    neg = df[df.insider == 0].sample(n=min(n_benign, int((df.insider == 0).sum())), random_state=seed)
    for frame in (pos, neg):
        for row in frame.itertuples(index=False):
            s = row_to_session(row)
            b = store.get(s["user_id"]) or store.get_or_create(s["user_id"])
            out = model.score(s, b)
            lvl = classify(out.score, t)
            samples.append((encode_state(lvl, out.score, len(out.triggered_rules), b.cold_start), lvl,
                            bool(row.insider)))
    return samples


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--episodes", type=int, default=40000)
    ap.add_argument("--sims-per-scenario", type=int, default=60)
    ap.add_argument("--benign-replay", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()

    cfg = get_config()
    out_path = args.output or cfg.path(cfg.rl.q_table_path)
    rng = random.Random(args.seed)
    print("Building labelled episodes …")
    samples = build_samples(cfg, args.sims_per_scenario, args.benign_replay, args.seed)
    rng.shuffle(samples)
    split = int(len(samples) * 0.8)
    train, test = samples[:split], samples[split:]
    print(f"  {len(samples)} samples ({sum(m for *_, m in samples)} malicious) → train {len(train)} / test {len(test)}")

    agent = QLearningAgent(out_path, alpha=cfg.rl.learning_rate, gamma=cfg.rl.discount_factor,
                           epsilon=cfg.rl.epsilon, seed=args.seed)
    agent.q, agent.visits, agent.updates = {}, {}, 0  # always train from scratch
    total_reward = 0.0
    for ep in range(args.episodes):
        state, level, malicious = train[ep % len(train)]
        rec = agent.recommend(state, level, explore=True)
        if rec.source == "rule_fallback":  # unseen state: explore uniformly so every action gets tried
            rec.action = rng.choice(ACTIONS)
        r = reward_from_ground_truth(rec.action, malicious)
        agent.update(state, rec.action, r)  # terminal episode (gamma has no effect)
        total_reward += r

    good = {True: {"BLOCK", "ESCALATE"}, False: {"ALLOW", "MONITOR"}}
    hits = rule_hits = 0
    for state, level, malicious in test:
        hits += agent.recommend(state, level).action in good[malicious]
        rule_hits += {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "ESCALATE"}[level] in good[malicious]
    agent.metadata = {
        "trained_with": "scripts/train_rl_policy.py", "episodes": args.episodes, "seed": args.seed,
        "samples": len(samples), "malicious_samples": int(sum(m for *_, m in samples)),
        "sources": ["attacker_agent simulations (8 scenarios)", "CERT r4.2 replay (insider window labels)"],
        "held_out_good_action_rate": round(hits / max(len(test), 1), 4),
        "rule_policy_good_action_rate": round(rule_hits / max(len(test), 1), 4),
        "mean_training_reward": round(total_reward / args.episodes, 4),
    }
    agent.save()
    print(f"Saved {out_path}")
    for k, v in agent.metadata.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
