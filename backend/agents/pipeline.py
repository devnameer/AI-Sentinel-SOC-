"""
LangGraph orchestration of the defensive pipeline.

    START ─► data_agent ─► behavior_agent ─► risk_agent ─► response_agent ─► END
                 │               │
                 └──── halted ───┴──────────────────────────────────────► END

The Attacker Agent is intentionally NOT part of this graph: it produces input
for the graph (simulated telemetry), just like a real adversary would.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from langgraph.graph import END, START, StateGraph

from agents.behavior_agent import BehaviorAgent
from agents.data_agent import DataAgent
from agents.response_agent import ResponseAgent
from agents.risk_agent import RiskAgent
from agents.state import SOCState

PIPELINE_ORDER = ["data_agent", "behavior_agent", "risk_agent", "response_agent"]


def _continue_or_end(next_node: str):
    def route(state: SOCState) -> str:
        return END if state.get("halted") else next_node
    return route


def build_graph(data: Optional[DataAgent] = None, behavior: Optional[BehaviorAgent] = None,
                risk: Optional[RiskAgent] = None, response: Optional[ResponseAgent] = None):
    g = StateGraph(SOCState)
    g.add_node("data_agent", data or DataAgent())
    g.add_node("behavior_agent", behavior or BehaviorAgent())
    g.add_node("risk_agent", risk or RiskAgent())
    g.add_node("response_agent", response or ResponseAgent())
    g.add_edge(START, "data_agent")
    g.add_conditional_edges("data_agent", _continue_or_end("behavior_agent"), ["behavior_agent", END])
    g.add_conditional_edges("behavior_agent", _continue_or_end("risk_agent"), ["risk_agent", END])
    g.add_edge("risk_agent", "response_agent")
    g.add_edge("response_agent", END)
    return g.compile()


_graph = None
_lock = threading.Lock()


def get_graph():
    global _graph
    if _graph is None:
        with _lock:
            if _graph is None:
                _graph = build_graph()
    return _graph


def reset_graph() -> None:
    global _graph
    _graph = None


def run_pipeline(request: Dict[str, Any], graph=None) -> SOCState:
    """Run one request through the four agents and return the final state."""
    initial: SOCState = {"request": request, "trace": [], "errors": [], "halted": False}
    return (graph or get_graph()).invoke(initial)
