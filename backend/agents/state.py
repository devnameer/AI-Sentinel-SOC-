"""
Shared LangGraph state for one pipeline run (one session or one network window).

Each agent reads what it needs and returns ONLY the keys it adds. ``trace`` and
``errors`` use list-append reducers, so every agent can contribute to them.
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Dict, List, Optional, TypedDict


class SOCState(TypedDict, total=False):
    # input (set by the caller)
    request: Dict[str, Any]          # {"source", "kind", "session"| "events" | "connections", "simulation"}
    # Data Agent
    source: str                      # replay | host | attacker | manual
    kind: str                        # behavior | network
    events: List[Dict[str, Any]]     # raw events kept for the Live Events table
    session: Dict[str, Any]          # normalised user session (behavior kind)
    connections: List[Dict[str, Any]]  # network window (network kind)
    ground_truth: Optional[bool]     # known label (simulations, CERT replay) — never shown to the models
    # agent outputs
    behavior: Dict[str, Any]
    risk: Dict[str, Any]
    response: Dict[str, Any]
    # bookkeeping
    trace: Annotated[List[Dict[str, Any]], operator.add]
    errors: Annotated[List[str], operator.add]
    halted: bool
