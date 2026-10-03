"""
Base class for the defensive agents.

``BaseAgent.__call__`` makes an agent usable directly as a LangGraph node:
it times the run, catches exceptions (a failing agent halts the run with a
readable error instead of a 500), and appends a trace record that the API
stores as real agent telemetry (latency, errors, decisions).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

from agents.state import SOCState
from core.config import get_config
from core.llm import LLMClient, get_llm_client
from tools.mcp_client import ToolClient

AGENT_INFO: Dict[str, Dict[str, str]] = {
    "data_agent": {"title": "Data Agent", "role": "Collects, normalises and aggregates security telemetry",
                   "input": "Raw events / dataset sessions", "output": "Normalised session or network window"},
    "behavior_agent": {"title": "Behavior Agent", "role": "ML anomaly detection against per-user baselines",
                       "input": "Session / network window", "output": "Anomaly score, rules, explanation"},
    "risk_agent": {"title": "Risk & Decision Agent", "role": "Contextual risk scoring and policy decision",
                   "input": "Anomaly result + context", "output": "Risk level and decision"},
    "response_agent": {"title": "Response Agent", "role": "Q-learning action selection with human approval",
                       "input": "Risk assessment", "output": "Recommended action / incident"},
    "attacker_agent": {"title": "Attacker Agent", "role": "Controlled attack simulation (red team)",
                       "input": "Scenario catalogue", "output": "Simulated telemetry with ground truth"},
}


class AgentHalt(Exception):
    """Raise inside an agent to stop the pipeline with a clean message."""


class BaseAgent:
    name = "base"

    def __init__(self, llm: LLMClient | None = None, tools: ToolClient | None = None):
        self.cfg = get_config()
        self._llm = llm
        self._tools = tools
        self.logger = logging.getLogger(f"soc.agents.{self.name}")

    @property
    def llm(self) -> LLMClient:
        return self._llm or get_llm_client()

    def tools(self) -> ToolClient:
        """A fresh client per run so the tool-call trace belongs to this run only."""
        return self._tools or ToolClient()

    @property
    def enabled(self) -> bool:
        section = getattr(self.cfg.agents, self.name, None)
        return bool(getattr(section, "enabled", True))

    def run(self, state: SOCState) -> Dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError

    def __call__(self, state: SOCState) -> Dict[str, Any]:
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        record: Dict[str, Any] = {"agent": self.name, "started_at": started.isoformat()}
        try:
            update = self.run(state) if self.enabled else self.skip(state)
            record.update(status="ok" if self.enabled else "skipped", summary=update.pop("_summary", ""))
            record["tool_calls"] = update.pop("_tool_calls", [])
            record["llm"] = update.pop("_llm", None)
        except AgentHalt as exc:
            update = {"halted": True, "errors": [f"{self.name}: {exc}"]}
            record.update(status="error", error=str(exc))
            self.logger.warning("Agent halted pipeline", extra={"agent": self.name, "reason": str(exc)})
        except Exception as exc:  # unexpected bug: keep the API alive, surface the error
            update = {"halted": True, "errors": [f"{self.name}: {type(exc).__name__}: {exc}"]}
            record.update(status="error", error=f"{type(exc).__name__}: {exc}")
            self.logger.exception("Agent crashed", extra={"agent": self.name})
        record["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        update.setdefault("trace", []).append(record)
        return update

    def skip(self, state: SOCState) -> Dict[str, Any]:
        """Behaviour when the agent is disabled in config.yaml (override if needed)."""
        return {"_summary": "disabled in config.yaml"}
