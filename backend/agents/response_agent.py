"""
Response Agent — action selection with a human in the loop.

1. Q-learning policy recommends ALLOW / MONITOR / ESCALATE / BLOCK for the
   discretised risk state (ml/q_learning.py). Unseen states use a rule fallback.
2. Guardrails clamp the action into the policy band (e.g. HIGH ≥ ESCALATE,
   LOW ≤ MONITOR) — the learned policy can never under-react to HIGH risk.
3. Execution mode:
      LOW                       → logged
      MEDIUM / HIGH (default)   → incident "awaiting_approval" → APPROVE / DENY on the dashboard
      HIGH + auto_execute       → auto_executed (opt-in in config.yaml)
   Actions are recorded (simulated containment); no real system is touched.
4. Optional LLM incident summary + playbook grounded in the RAG playbooks.

The analyst's APPROVE / DENY becomes the RL reward (api/services.py).
"""
from __future__ import annotations

from typing import Any, Dict, List

from agents.base import BaseAgent
from agents.resources import get_q_agent
from agents.state import SOCState
from core.llm import untrusted
from ml.q_learning import apply_guardrails, encode_state
from rag.retriever import format_context

DEFAULT_PLAYBOOK = {
    "data_exfiltration": ["Confirm the USB device / upload destination", "Compare accessed files with the baseline",
                          "Contact the user's manager before alerting the user", "Preserve device and proxy logs"],
    "pre_departure_data_theft": ["Review recent USB and file activity", "Check HR status of the user",
                                 "Restrict access to sensitive shares", "Preserve evidence"],
    "account_misuse": ["Verify the logon with the account owner out of band", "Force password reset and MFA",
                       "Inspect the source workstation for keyloggers"],
    "network": ["Identify target service and traffic pattern", "Rate-limit / filter at the edge",
                "Investigate the source host if internal"],
    "default": ["Review the triggered signals", "Check the user's recent history", "Decide on containment"],
}

SYSTEM_PROMPT = ("You are a SOC incident responder. Summarise the incident for an analyst and give a short, "
                 "concrete playbook. Use only the provided facts. Return strict JSON only.")


class ResponseAgent(BaseAgent):
    name = "response_agent"

    def skip(self, state: SOCState) -> Dict[str, Any]:
        r = state["risk"]
        return {"response": {"action": r["decision"], "execution": "logged", "requires_approval": False,
                             "policy": {"source": "disabled"}, "summary": "Response agent disabled.",
                             "playbook": []}, "_summary": "disabled"}

    def run(self, state: SOCState) -> Dict[str, Any]:
        if state.get("halted"):
            return {"_summary": "skipped (pipeline halted)"}
        b, r, cfg = state["behavior"], state["risk"], self.cfg
        level = r["risk_level"]
        rl_state = encode_state(level, r["risk_score"], len(b.get("triggered_rules", [])), bool(b.get("cold_start")))
        rec = get_q_agent().recommend(rl_state, level)
        action, guardrail = apply_guardrails(rec.action, level, cfg.risk.min_action, cfg.risk.max_action)

        if level in cfg.response.require_approval_for:
            execution = "auto_executed" if (level == "HIGH" and cfg.response.auto_execute_high_risk) \
                else "awaiting_approval"
        else:
            execution = "logged"

        summary, playbook, llm_meta = None, [], None
        tools = self.tools()
        if level != "LOW" and cfg.llm.features.response_summary and self.llm.enabled:
            summary, playbook, llm_meta = self._llm_summary(state, action, tools)
        if not summary:
            summary = self._template_summary(b, r, action)
            category = "network" if b["kind"] == "network" else b.get("threat_category", "default")
            playbook = DEFAULT_PLAYBOOK.get(category, DEFAULT_PLAYBOOK["default"]) if level != "LOW" else []

        response = {
            "action": action, "execution": execution, "requires_approval": execution == "awaiting_approval",
            "policy": {**rec.to_dict(), "recommended_action": rec.action, "guardrail": guardrail},
            "summary": summary, "summary_source": "llm" if llm_meta and llm_meta.get("ok") else "template",
            "playbook": playbook, "llm": llm_meta,
        }
        return {"response": response, "_summary": f"{action} ({execution}, policy={rec.source})",
                "_tool_calls": tools.calls, "_llm": llm_meta}

    def _llm_summary(self, state, action, tools):
        b, r = state["behavior"], state["risk"]
        query = f"playbook {b.get('threat_category', '')} {' '.join(b.get('mitre_techniques', []))} {action}"
        knowledge = (tools.call("search_knowledge", {"query": query, "k": 3}) or {}).get("results", [])
        facts = {"risk_level": r["risk_level"], "risk_score": r["risk_score"], "action": action,
                 "threat_category": b.get("threat_category"), "rules": b.get("triggered_rules"),
                 "mitre": b.get("mitre_techniques"), "user": b.get("user_id"), "device": b.get("device_id"),
                 "risk_factors": r.get("risk_factors"), "mitigating_factors": r.get("mitigating_factors")}
        prompt = (f"Incident facts (trusted): {facts}\nPlaybooks (trusted):\n{format_context(knowledge, 1200)}\n"
                  f"{untrusted('model explanation', b.get('explanation', ''), 600)}\n"
                  'Return JSON: {"summary": "2 sentences", "steps": ["3-5 short imperative steps"]}')
        parsed, res = self.llm.chat_json([{"role": "system", "content": SYSTEM_PROMPT},
                                          {"role": "user", "content": prompt}], max_tokens=300)
        meta = {"ok": parsed is not None, "provider": res.provider, "model": res.model,
                "latency_ms": res.latency_ms, "error": res.error or None}
        if not parsed or not parsed.get("summary"):
            return None, [], meta
        steps: List[str] = [str(s)[:200] for s in parsed.get("steps", []) if s][:6]
        return str(parsed["summary"])[:600], steps, meta

    @staticmethod
    def _template_summary(b, r, action) -> str:
        what = b.get("threat_category", "activity").replace("_", " ")
        return (f"{r['risk_level']} risk ({r['risk_score']:.2f}) {what} for {b.get('user_id')} on "
                f"{b.get('device_id') or 'unknown device'}. Recommended action: {action}. {r['recommended_action']}")
