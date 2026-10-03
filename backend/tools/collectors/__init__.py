"""
Host data collectors (read-only telemetry from the machine running the backend).

Each collector returns a list of ``StandardEvent`` (see schema.py). Collectors are
exposed to agents ONLY through the MCP tool ``collect_host_events`` with an
allow-list — the LLM can choose among them but can never run arbitrary code.

Privacy: browser history and Outlook e-mail metadata are personal data. They are
disabled by default (config.yaml › agents.data_agent.host_collectors).
"""
from __future__ import annotations

import importlib
import logging
import platform
import time
from dataclasses import dataclass
from typing import Callable, Dict, List

logger = logging.getLogger("soc.collectors")


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    module: str
    function: str
    description: str
    platforms: tuple = ("Windows", "Linux", "Darwin")
    privacy_sensitive: bool = False


COLLECTORS: Dict[str, CollectorSpec] = {c.name: c for c in [
    CollectorSpec("system", "system", "collect_system_snapshot", "Active logon sessions, idle time, uptime"),
    CollectorSpec("process", "process", "collect_running_processes",
                  "Suspicious (LOLBin), high-CPU or high-memory processes"),
    CollectorSpec("network", "network", "collect_network_connections",
                  "Active TCP/UDP connections with owning process"),
    CollectorSpec("file", "file", "collect_file_snapshot", "Files modified in the last hour (metadata only)"),
    CollectorSpec("browser", "browser", "collect_browser_history", "Chrome/Edge/Firefox history (last 24 h)",
                  privacy_sensitive=True),
    CollectorSpec("dns", "dns", "collect_dns_queries", "Windows DNS client cache", platforms=("Windows",)),
    CollectorSpec("usb", "usb_device", "collect_usb_device_history", "USB storage device history (registry)",
                  platforms=("Windows",)),
    CollectorSpec("registry", "registry", "collect_persistence_mechanisms", "Registry autorun persistence keys",
                  platforms=("Windows",)),
    CollectorSpec("windows_events", "windows_event", "collect_windows_events",
                  "Security/System event log (logons, failures, service installs)", platforms=("Windows",)),
    CollectorSpec("email", "email", "collect_outlook_emails", "Outlook e-mail metadata (no bodies)",
                  platforms=("Windows",), privacy_sensitive=True),
]}


def available(spec: CollectorSpec) -> bool:
    return platform.system() in spec.platforms


def list_collectors() -> List[dict]:
    return [{"name": c.name, "description": c.description, "available_on_this_host": available(c),
             "platforms": list(c.platforms), "privacy_sensitive": c.privacy_sensitive}
            for c in COLLECTORS.values()]


def run_collector(name: str, max_events: int = 300) -> dict:
    """Run one allow-listed collector and return JSON-serialisable events."""
    spec = COLLECTORS.get(name)
    if spec is None:
        return {"collector": name, "ok": False, "error": f"unknown collector '{name}'", "events": []}
    if not available(spec):
        return {"collector": name, "ok": False, "events": [],
                "error": f"'{name}' only runs on {', '.join(spec.platforms)} (this host: {platform.system()})"}
    start = time.perf_counter()
    try:
        module = importlib.import_module(f"tools.collectors.{spec.module}")
        func: Callable = getattr(module, spec.function)
        events = func()
        out = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in events][:max_events]
        return {"collector": name, "ok": True, "events": out, "count": len(out),
                "elapsed_ms": int((time.perf_counter() - start) * 1000)}
    except Exception as exc:  # a broken collector must not break the pipeline
        logger.warning("Collector failed", extra={"collector": name, "error": str(exc)})
        return {"collector": name, "ok": False, "error": f"{type(exc).__name__}: {exc}", "events": []}
