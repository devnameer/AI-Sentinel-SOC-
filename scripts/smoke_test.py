#!/usr/bin/env python
"""
End-to-end smoke test against RUNNING services (stdlib only, no paid APIs).

    Frontend (proxy) → Backend → Agents → ML → LLM (or template) → Response → Incident approval

Usage:
    python scripts/smoke_test.py                                   # backend only
    python scripts/smoke_test.py --frontend http://localhost:3000  # also checks the Next.js proxy
Env: SOC_API_TOKEN is sent automatically if set.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

PASSED, FAILED = [], []


def call(base: str, method: str, path: str, body=None, timeout: float = 180):
    headers = {"Content-Type": "application/json"}
    if os.environ.get("SOC_API_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['SOC_API_TOKEN']}"
    req = urllib.request.Request(base.rstrip("/") + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASSED if ok else FAILED).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  — ' + detail) if detail else ''}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:8000/api/v1")
    ap.add_argument("--frontend", default=None, help="e.g. http://localhost:3000 (checks /api/soc proxy)")
    a = ap.parse_args()
    b = a.backend

    print(f"Backend: {b}")
    s, h = call(b, "GET", "/system/health/")
    check("health endpoint", s == 200, f"status={h.get('status')}")
    llm = (h.get("components", {}).get("llm", {}) or {}).get("primary", {})
    print(f"        LLM: {llm.get('provider')} / {llm.get('model')} → {llm.get('status')} {llm.get('hint') or ''}")
    check("behaviour model loaded", h.get("components", {}).get("behavior_model", {}).get("status") == "loaded")

    s, r = call(b, "POST", "/events/ingest/", {"source": "replay", "count": 2})
    ok = s == 201 and len(r.get("analyses", [])) == 2
    check("replay ingest → full pipeline", ok, f"risk levels {[x['risk_level'] for x in r.get('analyses', [])]}")

    s, sim = call(b, "POST", "/attacks/simulate/", {"scenario_id": "usb_exfil_wikileaks", "seed": 1})
    an = sim.get("analysis") or {}
    check("attack simulation detected", s == 201 and sim.get("status") == "detected",
          f"status={sim.get('status')} score={an.get('score')} risk={an.get('risk_level')} action={an.get('action')}")

    s, ctl = call(b, "POST", "/attacks/simulate/", {"scenario_id": "benign_workday", "seed": 1})
    check("benign control not flagged", s == 201 and ctl.get("status") == "correctly_ignored",
          f"status={ctl.get('status')}")

    inc_id = an.get("incident_id")
    if inc_id:
        s, inc = call(b, "POST", f"/incidents/{inc_id}/decision/", {"decision": "approve", "note": "smoke test"})
        check("human approval recorded", s == 200 and inc.get("status") == "approved", inc.get("reference", ""))
    else:
        check("incident created for HIGH risk", False, "no incident id returned")

    s, ag = call(b, "GET", "/agents/")
    names = {x["name"]: x["processed"] for x in ag.get("results", [])}
    check("agent telemetry recorded", s == 200 and names.get("behavior_agent", 0) > 0, str(names))

    if a.frontend:
        s, h2 = call(a.frontend.rstrip("/") + "/api/soc", "GET", "/system/ping/")
        check("frontend proxy → backend", s == 200 and h2.get("status") == "ok")

    print(f"\n{len(PASSED)} passed, {len(FAILED)} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
