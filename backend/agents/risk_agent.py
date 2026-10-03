"""
Risk & Decision Agent — contextual risk scoring.

    base score (Behavior Agent)
      + LLM contextual adjustment   (optional, clamped to ±max_llm_adjustment)
      + repeat-offender penalty      (deterministic, from incident history via MCP)
      = adjusted risk score ─► LOW / MEDIUM / HIGH ─► policy decision

The LLM can only nudge the score inside a hard bound and must justify it with
risk / mitigating factors. Without an LLM the agent still works: the decision
is then purely policy-based (and labelled as such).

Removed from the original: the forced HIGH/ESCALATE for simulated attacks.
"""
from __future__ import annotations

from typing import Any, Dict, List

from click import prompt

from agents.base import BaseAgent
from agents.state import SOCState
from core.llm import untrusted
from rag.retriever import format_context

DECISION_BY_LEVEL = {"LOW": "ALLOW", "MEDIUM": "MONITOR", "HIGH": "ESCALATE"}

RECOMMENDED_ACTION = {
    ("LOW", None): "Log the event for the audit trail.",
    ("MEDIUM", "data_exfiltration"): "Increase monitoring of removable media and uploads; notify the team lead.",
    ("MEDIUM", "pre_departure_data_theft"): "Watch-list the user and review recent file and USB activity with HR.",
    ("MEDIUM", "account_misuse"): "Verify the logon with the account owner; require MFA re-authentication.",
    ("MEDIUM", None): "Monitor closely and prepare an investigation if signals repeat.",
    ("HIGH", "data_exfiltration"): "Restrict removable storage and uploads for the account; open an incident.",
    ("HIGH", "pre_departure_data_theft"): "Restrict data access and preserve evidence; involve HR and legal.",
    ("HIGH", "account_misuse"): "Revoke sessions, reset credentials and isolate the source workstation.",
    ("HIGH", None): "Escalate to the SOC immediately and contain the affected asset.",
}

SYSTEM_PROMPT = (
    "You are the risk analyst of a SOC. Given a model detection and context, decide whether the "
    "risk should be adjusted up or down. Base your answer only on the provided facts. "
    "Return strict JSON only."
)


def classify(score: float, thresholds: Dict[str, float]) -> str:
    """LOW below low_max (same boundary as the anomaly flag), MEDIUM up to medium_max, HIGH above."""
    if score < thresholds.get("low_max", 0.4):
        return "LOW"
    if score <= thresholds.get("medium_max", 0.7):
        return "MEDIUM"
    return "HIGH"


def recommended_action(level: str, category: str) -> str:
    return RECOMMENDED_ACTION.get((level, category)) or RECOMMENDED_ACTION.get((level, None)) \
        or RECOMMENDED_ACTION[("LOW", None)]


class RiskAgent(BaseAgent):
    name = "risk_agent"

    def skip(self, state: SOCState) -> Dict[str, Any]:
        b = state["behavior"]
        level = classify(b["score"], self.cfg.risk.thresholds)
        return {"risk": self._result(b, b["score"], 0.0, 0.0, level, DECISION_BY_LEVEL[level], [], [],
                                     "Risk agent disabled — base score used as-is.", "disabled", {}),
                "_summary": "disabled — base score used"}

    def run(self, state: SOCState) -> Dict[str, Any]:
        if state.get("halted"):
            return {"_summary": "skipped (pipeline halted)"}
        b = state["behavior"]
        cfg = self.cfg
        tools = self.tools()
        base = float(b["score"])
        user = b.get("user_id", "")

        policy = tools.call("get_risk_policy")
        thresholds = policy.get("thresholds") or cfg.risk.thresholds
        history = tools.call("get_user_incident_history",
                             {"user_id": user, "hours": cfg.agents.risk_agent.repeat_offender.window_hours})
        context = {"incident_history": history if "error" not in history else {"available": False},
                   "baseline_confidence": b.get("confidence"), "cold_start": b.get("cold_start")}

        risk_factors: List[str] = []
        mitigating: List[str] = []
        llm_adj, reasoning, method, llm_meta = 0.0, "", "policy", None
        if b.get("cold_start"):
            mitigating.append("New user: baseline from population averages (low confidence)")
        if len(b.get("triggered_rules", [])) >= 3:
            risk_factors.append(f"{len(b['triggered_rules'])} independent signals in one session")

        use_llm = cfg.llm.features.risk_assessment and (b["flagged"] or not cfg.llm.only_for_flagged_events)
        if use_llm and self.llm.enabled:
            knowledge = (tools.call("search_knowledge", {"query": "risk policy mitigating aggravating factors "
                                                         + b.get("threat_category", ""), "k": 2}) or {}
                         ).get("results", [])
            parsed, llm_meta = self._llm_assess(state, b, context, knowledge)
            if parsed is not None:
                bound = cfg.agents.risk_agent.max_llm_adjustment
                try:
                    raw = float(parsed.get("risk_adjustment", 0.0))
                except (TypeError, ValueError):
                    raw = 0.0
                llm_adj = max(-bound, min(bound, raw))
                risk_factors += [str(x)[:200] for x in parsed.get("risk_factors", [])][:5]
                mitigating += [str(x)[:200] for x in parsed.get("mitigating_factors", [])][:5]
                reasoning = str(parsed.get("reasoning", ""))[:600]
                if abs(raw - llm_adj) > 1e-6:
                    reasoning += f" (LLM proposed {raw:+.2f}; clamped to {llm_adj:+.2f})"
                method = "policy+llm"

        # deterministic repeat-offender rule (preserved from the original agent)
        ro = cfg.agents.risk_agent.repeat_offender
        penalty = 0.0
        prior = int(history.get("medium_or_high", 0)) if isinstance(history, dict) else 0
        if b["flagged"] and prior >= ro.min_prior_events:
            penalty = ro.penalty
            risk_factors.append(f"Repeat offender: {prior} medium/high events in the last {ro.window_hours} h")

        adjusted = round(max(0.0, min(1.0, base + llm_adj + penalty)), 4)
        level = classify(adjusted, thresholds)
        decision = DECISION_BY_LEVEL[level]
        if penalty and decision in ("ALLOW", "MONITOR"):
            decision = "ESCALATE"
        if not reasoning:
            reasoning = (f"Policy decision: adjusted score {adjusted:.2f} falls in the {level} band "
                         f"(LOW < {thresholds['low_max']}, MEDIUM ≤ {thresholds['medium_max']}).")
        result = self._result(b, base, llm_adj, penalty, level, decision, risk_factors, mitigating,
                              reasoning, method, context)
        result["llm"] = llm_meta
        return {"risk": result, "_summary": f"{level} risk {adjusted:.2f} → {decision}",
                "_tool_calls": tools.calls, "_llm": llm_meta}

    def _result(self, b, base, llm_adj, penalty, level, decision, rf, mf, reasoning, method, context):
        adjusted = round(max(0.0, min(1.0, base + llm_adj + penalty)), 4)
        return {
            "base_score": round(base, 4), "llm_adjustment": round(llm_adj, 4),
            "repeat_offender_penalty": round(penalty, 4), "risk_score": round(adjusted, 4),
            "risk_level": level, "decision": decision,
            "recommended_action": recommended_action(level, b.get("threat_category", "")),
            "risk_factors": rf, "mitigating_factors": mf, "reasoning": reasoning,
            "method": method, "context": context,
        }

    def _llm_assess(self, state, b, context, knowledge):
        facts = {k: b.get(k) for k in ("kind", "score", "verdict", "triggered_rules", "threat_category",
                                       "mitre_techniques", "confidence", "cold_start")}
        bound = self.cfg.agents.risk_agent.max_llm_adjustment
        observed = state.get("session") or {"connections_sample": (state.get("connections") or [])[:5]}
        
        prompt = (
        f"Detection (trusted): {facts}\n"
        f"Context (trusted): {context}\n"
        f"Policy knowledge (trusted): {format_context(knowledge, 900)}\n"
        f"{untrusted} (observed activity)\n"
        f"Return ONLY valid JSON. Do not use markdown, code fences, "
        f"explanations, or any text outside the JSON object. "
        f"Use exactly these keys: "
        f'"risk_adjustment", "risk_factors", "mitigating_factors", "reasoning". '
        f'"risk_adjustment" must be a number between {bound} and {bound}. '
        f'"risk_factors" and "mitigating_factors" must be short lists. '
        f'"reasoning" must be one short sentence.'
    )

        parsed, res = self.llm.chat_json(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=600,
        )
        # prompt = (
        #     f"Detection (trusted): {facts}\n"
        #     f"Context (trusted): {context}\n"
        #     f"Policy knowledge (trusted):\n{format_context(knowledge, 900)}\n"
        #     f"{untrusted('observed activity', observed, 800)}\n"
        #     f"Return JSON with keys: \"risk_adjustment\" (number between -{bound} and {bound}), "
        #     "\"risk_factors\" (list of short strings), \"mitigating_factors\" (list), \"reasoning\" (one or two sentences)."
        # )
        # parsed, res = self.llm.chat_json([{"role": "system", "content": SYSTEM_PROMPT},
        #                                   {"role": "user", "content": prompt}], max_tokens=300)

        meta = {
            "ok": parsed is not None,
            "provider": res.provider,
            "model": res.model,
            "latency_ms": res.latency_ms,
            "error": res.error or None,
        }
        return parsed, meta
