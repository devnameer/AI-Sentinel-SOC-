"""
Behavior Agent — ML detection + explanation.

1. Score: insider-threat model (sessions) or network model (connection windows).
   All scoring is deterministic ML/rules; the LLM never changes the score here.
2. Context: rule explanations + knowledge-base passages via MCP tools (RAG).
3. Explain: the LLM writes a short analyst note grounded in the model output and
   retrieved context. Template fallback when the LLM is off/unavailable.
4. Learn: score-gated baseline update (skipped for simulations so red-team
   exercises never alter a real user's baseline).

Removed from the original: the "simulated attack override" that forced every
simulated attack to score 0.95. Detection of simulations is now real.
"""
from __future__ import annotations

from typing import Any, Dict, List

from agents.base import AgentHalt, BaseAgent
from agents.resources import get_baseline_store
from agents.state import SOCState
from core.llm import untrusted
from ml.behavior_model import ModelUnavailable, get_behavior_model
from ml.network_model import get_network_model
from rag.retriever import format_context

RULE_TO_MITRE = {
    "usb_device_connected": "T1052.001", "usb_first_time": "T1052.001", "exfil_domain_visited": "T1567",
    "unknown_device": "T1078", "file_download_volume_extreme": "T1005", "high_sensitivity_file_access": "T1005",
}

SYSTEM_PROMPT = (
    "You are a SOC analyst explaining a machine-learning detection to a colleague. "
    "Use only the facts provided. Write at most 3 short sentences: what the model found, "
    "the most likely scenario, and what to check next. No preamble, no bullet points."
)


def threat_category(rules: List[str], kind: str, attack_label: str | None = None) -> str:
    if kind == "network":
        return attack_label or "network_anomaly"
    r = set(rules)
    if {"exfil_domain_visited", "usb_first_time"} & r or ({"usb_device_connected"} <= r and
                                                         "file_download_volume_extreme" in r):
        return "data_exfiltration"
    if "jobsearch_domain_visited" in r:
        return "pre_departure_data_theft"
    if "unknown_device" in r:
        return "account_misuse"
    if r:
        return "anomalous_behavior"
    return "normal_activity"


class BehaviorAgent(BaseAgent):
    name = "behavior_agent"

    def skip(self, state: SOCState) -> Dict[str, Any]:
        raise AgentHalt("behavior_agent is disabled — nothing can be scored")

    def run(self, state: SOCState) -> Dict[str, Any]:
        if state.get("halted"):
            return {"_summary": "skipped (pipeline halted)"}
        tools = self.tools()
        if state.get("kind") == "network":
            result = self._score_network(state)
        else:
            result = self._score_session(state)

        rules = result["triggered_rules"]
        explanations = tools.call("explain_rules", {"rule_ids": rules}) if rules else {}
        knowledge: List[dict] = []
        want_llm = self.cfg.llm.features.behavior_explanation and (
            result["flagged"] or not self.cfg.llm.only_for_flagged_events)
        if result["flagged"]:
            query = f"{result['threat_category'].replace('_', ' ')} " + " ".join(r.replace("_", " ") for r in rules[:5])
            knowledge = (tools.call("search_knowledge", {"query": query, "k": 3}) or {}).get("results", [])

        llm_meta = None
        if want_llm and self.llm.enabled:
            text, llm_meta = self._llm_explain(state, result, explanations, knowledge)
        else:
            text = None
        if text:
            result.update(explanation=text, explanation_source="llm")
        else:
            result.update(explanation=self._template(state, result), explanation_source="template")
        result["rule_explanations"] = explanations if isinstance(explanations, dict) else {}
        result["knowledge"] = [{"source": k["source"], "title": k["title"]} for k in knowledge]
        result["llm"] = llm_meta
        summary = f"score {result['score']:.2f} ({result['verdict']}){' FLAGGED' if result['flagged'] else ''}"
        return {"behavior": result, "_summary": summary, "_tool_calls": tools.calls, "_llm": llm_meta}

    # ── scoring ───────────────────────────────────────────────────────────
    def _score_session(self, state: SOCState) -> Dict[str, Any]:
        session = state["session"]
        store = get_baseline_store()
        baseline = store.get_or_create(session["user_id"])
        try:
            scored = get_behavior_model().score(session, baseline)
        except ModelUnavailable as exc:
            raise AgentHalt(str(exc)) from exc
        result = scored.to_dict()
        confidence = "low" if baseline.cold_start else "medium" if baseline.observation_days < 20 else "high"
        if state.get("source") == "attacker":
            result["baseline_update"] = "skipped (simulation)"
        elif (state.get("request") or {}).get("dry_run"):
            result["baseline_update"] = "skipped (dry run)"
        else:
            result["baseline_update"] = store.update_after_scoring(
                session["user_id"], session, scored.score, self.cfg.ml.behavior.baseline_update_threshold)
        mitre = sorted({RULE_TO_MITRE[r] for r in scored.triggered_rules if r in RULE_TO_MITRE})
        result.update(kind="behavior", user_id=session["user_id"], device_id=session["pc"],
                      confidence=confidence, cold_start=baseline.cold_start, baseline=baseline.summary(),
                      mitre_techniques=mitre if scored.flagged else [],
                      threat_category=threat_category(scored.triggered_rules, "behavior") if scored.flagged
                      else "normal_activity",
                      model="isolation_forest" if scored.scoring_mode == "isolation_forest"
                      else "isolation_forest+rules")
        return result

    def _score_network(self, state: SOCState) -> Dict[str, Any]:
        conns = state["connections"]
        model = get_network_model()
        if model.status()["status"] == "unavailable":
            self.logger.warning("Network ML unavailable — rules only", extra=model.errors)
        r = model.score(conns)
        first = conns[0]
        verdict = "CRITICAL" if r["score"] >= 0.85 else "HIGH" if r["score"] >= 0.65 else \
            "MEDIUM" if r["flagged"] else "LOW"
        return {
            "kind": "network", "score": r["score"], "flagged": r["flagged"], "threshold": r["threshold"],
            "verdict": verdict, "triggered_rules": r["triggered_rules"], "model": f"network_{r['mode']}",
            "network": r, "user_id": str(first.get("user_id") or first.get("src_ip") or "network"),
            "device_id": str(first.get("device_id") or first.get("src_ip") or ""),
            "confidence": "high" if r["mode"] == "hybrid" else "medium", "cold_start": False,
            "mitre_techniques": [r["mitre_technique"]] if r.get("mitre_technique") else [],
            "threat_category": threat_category(r["triggered_rules"], "network", r.get("attack_label"))
            if r["flagged"] else "normal_activity",
            "baseline_update": "n/a",
        }

    # ── explanation ───────────────────────────────────────────────────────
    def _llm_explain(self, state, result, explanations, knowledge):
        facts = {k: result.get(k) for k in ("kind", "score", "verdict", "flagged", "threshold", "model",
                                            "triggered_rules", "threat_category", "mitre_techniques")}
        if result["kind"] == "behavior":
            facts["if_score"], facts["rule_score"] = result.get("if_score"), result.get("rule_score")
            facts["dimension_scores"] = result.get("dimension_scores")
            context = {"session": state["session"], "baseline": result.get("baseline")}
        else:
            facts["network_model"] = {k: result["network"].get(k) for k in
                                      ("model_score", "if_score", "catboost_probability", "attack_label")}
            context = {"connections_sample": state["connections"][:5]}
        prompt = (
            f"Model output (trusted): {facts}\n"
            f"Rule meanings (trusted): {explanations}\n"
            f"Knowledge base (trusted):\n{format_context(knowledge, 1200)}\n"
            f"{untrusted('observed activity', context)}\n"
            "Explain this detection."
        )
        res = self.llm.chat([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
                            max_tokens=180)
        meta = {"ok": res.ok, "provider": res.provider, "model": res.model, "latency_ms": res.latency_ms,
                "error": res.error or None}
        return (res.text if res.ok and res.text else None), meta

    @staticmethod
    def _template(state, r) -> str:
        if r["kind"] == "network":
            n = r["network"]
            base = (f"The network model scored this {n['connections']}-connection window {r['score']:.2f} "
                    f"({r['verdict']}, mode {n['mode']}).")
            if r["flagged"]:
                base += f" Pattern: {n.get('attack_label') or 'anomalous traffic'}"
                base += f" ({', '.join(r['mitre_techniques'])})." if r["mitre_techniques"] else "."
            return base + (f" Signals: {', '.join(r['triggered_rules'][:4])}." if r["triggered_rules"] else "")
        parts = [f"Behaviour score {r['score']:.2f} for {r['user_id']} ({r['verdict']}): "
                 f"Isolation Forest {r['if_score']:.2f}, rule score {r['rule_score']:.2f}."]
        if r["triggered_rules"]:
            parts.append(f"Signals: {', '.join(x.replace('_', ' ') for x in r['triggered_rules'])}.")
        top = max(r["dimension_scores"], key=r["dimension_scores"].get)
        if r["dimension_scores"][top] > 0:
            parts.append(f"Strongest deviation from baseline: {top} ({r['dimension_scores'][top]:.2f}).")
        if r.get("cold_start"):
            parts.append("New user — baseline built from population averages, confidence is low.")
        return " ".join(parts)
