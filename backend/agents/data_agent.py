"""
Data Agent — collection, normalisation and aggregation.

Sources
* replay   – real labelled CERT r4.2 sessions (default demo source)
* host     – read-only collectors on this machine, called through the MCP tool
             ``collect_host_events``; optionally the LLM picks which collectors to run
* attacker – raw events produced by the Attacker Agent (ground truth attached)
* manual   – a session posted to the API

Raw events are aggregated into
* one behaviour SESSION per user (input of the insider-threat model), and
* NETWORK WINDOWS of N connections (input of the network model).

Fix vs. the original: unknown users are no longer mapped to a random CERT user;
they get their own cold-start baseline (lower confidence, reported in the UI).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from agents.base import AgentHalt, BaseAgent
from agents.resources import get_baseline_store
from agents.state import SOCState
from core.llm import untrusted
from ml.features import EXFIL_DOMAINS, JOBSEARCH_DOMAINS, normalize_session
from tools.collectors import COLLECTORS


def _parse_ts(value: Any) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.now()


def _domain_matches(domain: str, known: set) -> bool:
    d = (domain or "").lower()
    return any(d == k or d.endswith("." + k) for k in known)


def aggregate_session(user_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Turn one user's raw events into the session schema of the behaviour model."""
    events = sorted(events, key=lambda e: str(e.get("timestamp", "")))
    first, last = _parse_ts(events[0].get("timestamp")), _parse_ts(events[-1].get("timestamp"))
    hour = first.hour
    s: Dict[str, Any] = {
        "user_id": user_id, "pc": events[0].get("device_id", ""), "session_start": first.isoformat(),
        "hour_of_day": hour, "is_weekend": int(first.weekday() >= 5),
        "is_outside_hours": int(hour < 8 or hour >= 18),
        "duration_minutes": max((last - first).total_seconds() / 60.0, 1.0),
        "file_count": 0, "max_sensitivity": 0, "usb_connected": 0, "usb_first_time": 0,
        "email_count": 0, "has_ext_email": 0, "visited_exfil_domain": 0, "visited_jobsearch_domain": 0,
    }
    for e in events:
        et, cat, md = e.get("event_type", ""), e.get("event_category", ""), e.get("metadata") or {}
        if et == "file_access" or cat == "file":
            s["file_count"] += 1
            s["max_sensitivity"] = max(s["max_sensitivity"], int(md.get("sensitivity_level") or 0))
            if md.get("is_usb"):
                s["usb_connected"] = 1
        if et == "device_connect" and (md.get("is_usb") or md.get("device_type") == "usb_storage"):
            s["usb_connected"] = 1
            if md.get("first_time_device"):
                s["usb_first_time"] = 1
        if et in ("email_sent", "email_received") or cat == "email":
            s["email_count"] += 1
            if md.get("is_external"):
                s["has_ext_email"] = 1
        if et == "http_request" or cat == "web":
            domain = md.get("domain") or ""
            s["visited_exfil_domain"] |= int(_domain_matches(domain, EXFIL_DOMAINS))
            s["visited_jobsearch_domain"] |= int(_domain_matches(domain, JOBSEARCH_DOMAINS))
    return normalize_session(s)


def connections_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    conns = []
    for e in events:
        if e.get("event_type") != "network_connection":
            continue
        md = e.get("metadata") or {}
        conns.append({
            "timestamp": e.get("timestamp"), "protocol": md.get("protocol") or "TCP",
            "src_ip": md.get("src_ip"), "dst_ip": md.get("dst_ip"),
            "src_port": md.get("src_port"), "dst_port": md.get("dst_port"),
            # keep None: host snapshots (psutil) do not know byte counts — that is "unknown", not 0
            "bytes_sent": md.get("bytes_sent"), "bytes_received": md.get("bytes_received"),
            "process_name": md.get("process_name"), "user_id": e.get("user_id"), "device_id": e.get("device_id"),
        })
    return conns


def session_summary_event(session: Dict[str, Any], source: str) -> Dict[str, Any]:
    """A display event for sources that deliver whole sessions (the CERT replay)."""
    signals = [k for k in ("usb_connected", "visited_exfil_domain", "visited_jobsearch_domain", "has_ext_email",
                           "is_outside_hours") if session.get(k)]
    return {
        "timestamp": session["session_start"], "user_id": session["user_id"], "device_id": session["pc"],
        "event_type": "user_session", "event_category": "session", "action": "session_closed",
        "resource": f"session://{session['user_id']}@{session['pc']}", "source": source,
        "metadata": {"file_count": session["file_count"], "email_count": session["email_count"],
                     "duration_minutes": round(session["duration_minutes"], 1), "signals": signals},
    }


class DataAgent(BaseAgent):
    name = "data_agent"

    # ── collection (called before the graph, may produce several runs) ────
    def collect_host(self, collectors: Optional[List[str]] = None) -> Dict[str, Any]:
        cfg = self.cfg.agents.data_agent
        tools = self.tools()
        chosen = [c for c in (collectors or cfg.host_collectors) if c in COLLECTORS]
        selection = {"method": "config", "reasoning": "collectors from config.yaml"}
        if not collectors and self.cfg.llm.features.data_tool_selection:
            chosen, selection = self._llm_select_collectors(tools, chosen)
        result = tools.call("collect_host_events", {"collectors": chosen,
                                                    "max_events": cfg.max_events_per_collection})
        events = result.get("events", []) if isinstance(result, dict) else []
        return {"events": events, "collectors": chosen, "selection": selection,
                "results": result.get("results", []) if isinstance(result, dict) else [],
                "tool_calls": tools.calls}

    def _llm_select_collectors(self, tools, default: List[str]):
        catalogue = tools.call("list_collectors")
        options = [c for c in catalogue.get("collectors", []) if c.get("available_on_this_host")]
        prompt = (
            "You are the Data Agent of a SOC. Choose which read-only host collectors to run for a routine "
            "security sweep. Prefer few, high-value collectors; avoid privacy-sensitive ones unless needed.\n"
            f"{untrusted('available collectors', options)}\n"
            'Return JSON: {"tools": ["name", ...], "reasoning": "one sentence"}'
        )
        parsed, res = self.llm.chat_json([{"role": "user", "content": prompt}], max_tokens=150)
        valid = {c["name"] for c in options}
        picked = [t for t in (parsed or {}).get("tools", []) if t in valid][:6]
        if not picked:
            return default, {"method": "config", "reasoning": f"LLM unavailable/invalid ({res.error or 'no tools'})"}
        return picked, {"method": "llm", "reasoning": str((parsed or {}).get("reasoning", ""))[:300],
                        "provider": res.provider, "model": res.model}

    def build_requests(self, events: List[Dict[str, Any]], source: str,
                       extra: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Split raw events into pipeline requests (behaviour sessions + network windows)."""
        extra = extra or {}
        by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            if e.get("event_type") != "network_connection":
                by_user[str(e.get("user_id") or "unknown")].append(e)
        requests = [{"source": source, "kind": "behavior", "events": evs, **extra} for evs in by_user.values()]
        conns_events = [e for e in events if e.get("event_type") == "network_connection"]
        size = self.cfg.agents.data_agent.network_window_size
        for i in range(0, len(conns_events), size):
            requests.append({"source": source, "kind": "network", "events": conns_events[i:i + size], **extra})
        return requests

    # ── graph node ────────────────────────────────────────────────────────
    def run(self, state: SOCState) -> Dict[str, Any]:
        req = state.get("request") or {}
        source = req.get("source", "manual")
        kind = req.get("kind", "behavior")
        events: List[Dict[str, Any]] = list(req.get("events") or [])
        out: Dict[str, Any] = {"source": source, "kind": kind, "ground_truth": req.get("ground_truth")}

        if kind == "network":
            conns = req.get("connections") or connections_from_events(events)
            if not conns:
                raise AgentHalt("network request contains no connections")
            out.update(connections=conns, events=events,
                       _summary=f"network window of {len(conns)} connections from {source}")
            return out

        if req.get("session"):
            session = normalize_session(req["session"])
            if not events:
                events = [session_summary_event(session, source)]
        elif events:
            user = str(events[0].get("user_id") or "unknown")
            session = aggregate_session(user, events)
        else:
            raise AgentHalt("request has neither a session nor events")
        if not session["user_id"]:
            raise AgentHalt("session has no user_id")

        store = get_baseline_store()
        known = store.get(session["user_id"]) is not None
        if not known:
            store.get_or_create(session["user_id"], department=req.get("department", "unassigned"))
        out.update(session=session, events=events,
                   _summary=(f"{source}: session for {session['user_id']} ({len(events)} events"
                             f"{', new user → cold-start baseline' if not known else ''})"))
        return out
