"""
Attacker Agent — controlled red-team SIMULATION (no real attack capability).

It only fabricates *telemetry* (log events) that looks like a known attack
scenario and feeds it into the defensive pipeline, with the ground truth
attached. It never executes code, scans hosts or sends packets.

Insider scenarios are built from the three CERT r4.2 scenarios and target the
real baseline of a CERT insider user, so detection depends on how far the
simulated behaviour deviates from that user's normal habits — exactly like a
real detection. A benign control scenario measures false positives.

Network scenarios produce connection records for the network model.

Optional: with ``llm.features.attack_planning`` the LLM picks the next scenario
(it may only choose an ID from the catalogue).
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from agents.base import BaseAgent
from agents.resources import get_baseline_store
from ml.baselines import UserBaseline

# CERT r4.2 insider users by scenario (from the original attack_patterns.json answer key)
CERT_INSIDERS = {
    1: ["AAM0658", "AJR0932", "BDV0168", "BIH0745", "BLS0678", "BTL0226", "CAH0936", "DCH0843", "EHB0824",
        "EHD0584", "FMG0527", "FTM0406", "GHL0460", "HJB0742", "JMB0308"],
    2: ["AAF0535", "ABC0174", "AKR0057", "CCL0068", "CEJ0109", "CQW0652", "DIB0285", "DRR0162", "EDB0714",
        "EGD0132"],
    3: ["BBS0039", "BSS0369", "CCA0046", "CSC0217", "GTD0219"],
}


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    kind: str              # behavior | network
    tactic: str
    technique: str         # MITRE ATT&CK ID
    severity: str
    malicious: bool        # ground truth
    description: str
    cert_scenario: Optional[int] = None


SCENARIOS: Dict[str, Scenario] = {s.id: s for s in [
    Scenario("usb_exfil_wikileaks", "After-hours USB exfiltration to WikiLeaks", "behavior", "Exfiltration",
             "T1052.001", "critical", True,
             "CERT scenario 1: first-time USB use late at night, bulk file copy, upload to wikileaks.org.", 1),
    Scenario("jobhunt_usb_theft", "Job hunting followed by USB data theft", "behavior", "Exfiltration",
             "T1052.001", "high", True,
             "CERT scenario 2: job-site browsing, external e-mail and heavy USB file copying before leaving.", 2),
    Scenario("keylogger_impersonation", "Keylogger + supervisor impersonation", "behavior", "Credential Access",
             "T1056.001", "critical", True,
             "CERT scenario 3: logon on another user's workstation, first-time USB (keylogger), mass e-mail.", 3),
    Scenario("bulk_sensitive_download", "Bulk download of sensitive files", "behavior", "Collection",
             "T1005", "high", True, "Working-hours access to many files above the user's sensitivity level."),
    Scenario("benign_workday", "Normal working day (control)", "behavior", "—", "—", "none", False,
             "A session that matches the user's baseline. Used to measure false positives."),
    Scenario("dns_amplification", "DNS reflection amplification", "network", "Impact", "T1498.002", "high", True,
             "Small UDP/53 queries producing very large responses towards one victim."),
    Scenario("syn_flood", "TCP SYN flood", "network", "Impact", "T1498.001", "critical", True,
             "Hundreds of TCP connection attempts to one service without any response."),
    Scenario("port_scan", "Network service discovery (port scan)", "network", "Discovery", "T1046", "medium",
             True, "One source probing many ports on a single target host."),
]}


class AttackerAgent(BaseAgent):
    name = "attacker_agent"

    def __init__(self, *args, seed: Optional[int] = None, **kwargs):
        super().__init__(*args, **kwargs)
        seed = seed if seed is not None else self.cfg.agents.attacker_agent.seed
        self.rng = random.Random(seed)

    def catalogue(self) -> List[dict]:
        return [s.__dict__ | {"targets": CERT_INSIDERS.get(s.cert_scenario, [])[:5]} for s in SCENARIOS.values()]

    # ── planning ──────────────────────────────────────────────────────────
    def plan(self, history: List[dict]) -> tuple[str, dict]:
        """Choose the next scenario: LLM (optional, catalogue-constrained) or round-robin over least-tested."""
        if self.cfg.llm.features.attack_planning and self.llm.enabled:
            stats = {s: {"runs": 0, "detected": 0} for s in SCENARIOS}
            for h in history:
                if h.get("scenario_id") in stats:
                    stats[h["scenario_id"]]["runs"] += 1
                    stats[h["scenario_id"]]["detected"] += int(h.get("status") == "detected")
            prompt = ("You are a red-team planner testing a SOC's detections in a lab. Pick the scenario most "
                      "worth testing next (prefer ones rarely tested or rarely detected).\n"
                      f"Catalogue: {[{'id': s.id, 'name': s.name} for s in SCENARIOS.values()]}\n"
                      f"Results so far: {stats}\n"
                      'Return JSON: {"scenario_id": "<id from catalogue>", "reasoning": "one sentence"}')
            parsed, res = self.llm.chat_json([{"role": "user", "content": prompt}], max_tokens=120)
            sid = (parsed or {}).get("scenario_id")
            if sid in SCENARIOS:
                return sid, {"method": "llm", "reasoning": str(parsed.get("reasoning", ""))[:300],
                             "provider": res.provider, "model": res.model}
        counts = {s: 0 for s in SCENARIOS}
        for h in history:
            counts[h.get("scenario_id")] = counts.get(h.get("scenario_id"), 0) + 1
        least = min(counts.values())
        sid = self.rng.choice([s for s, c in counts.items() if c == least])
        return sid, {"method": "least_tested", "reasoning": "round-robin over the least-tested scenarios"}

    # ── generation ────────────────────────────────────────────────────────
    def build(self, scenario_id: str, target_user: Optional[str] = None) -> Dict[str, Any]:
        """Return a pipeline request with simulated events and the ground truth."""
        sc = SCENARIOS.get(scenario_id)
        if sc is None:
            raise ValueError(f"unknown scenario '{scenario_id}'")
        if sc.kind == "network":
            events = NETWORK_GENERATORS[sc.id](self.rng, datetime.now())
            target = events[0]["metadata"]["dst_ip"]
            device = events[0]["device_id"]
        else:
            store = get_baseline_store()
            if target_user:
                target = target_user
            else:
                pool = [u for u in CERT_INSIDERS.get(sc.cert_scenario, []) if store.get(u)] or store.users()
                target = self.rng.choice(pool)
            baseline = store.get_or_create(target)
            events = BEHAVIOR_GENERATORS[sc.id](self.rng, baseline)
            device = events[0]["device_id"]
        for e in events:
            e["metadata"].update(is_simulated=True, attack_type=sc.id, mitre_technique=sc.technique,
                                 severity=sc.severity)
            e["source"] = "attacker_agent"
        return {"source": "attacker", "kind": sc.kind, "events": events, "ground_truth": sc.malicious,
                "simulation": {"scenario_id": sc.id, "name": sc.name, "technique": sc.technique,
                               "tactic": sc.tactic, "target": target, "device": device,
                               "expected_malicious": sc.malicious}}


# ── event helpers ──────────────────────────────────────────────────────────
def _event(ts: datetime, user: str, pc: str, etype: str, cat: str, action: str, resource: str, **md) -> dict:
    return {"timestamp": ts.isoformat(timespec="seconds"), "user_id": user, "device_id": pc, "event_type": etype,
            "event_category": cat, "action": action, "resource": resource, "metadata": dict(md)}


def _session_day(rng: random.Random, weekday: bool = True) -> datetime:
    day = datetime.now().replace(minute=0, second=0, microsecond=0)
    while (day.weekday() < 5) != weekday:
        day -= timedelta(days=1)
    return day


def _at_hour(day: datetime, hour: float) -> datetime:
    return day.replace(hour=int(hour) % 24, minute=0) + timedelta(minutes=int((hour % 1) * 60))


def _files(rng, start, user, pc, n, sens_choices, usb=False) -> List[dict]:
    return [_event(start + timedelta(minutes=2 + i * rng.uniform(0.2, 1.0)), user, pc, "file_access", "file",
                   "copy" if usb else "open", f"\\\\fileserver\\share\\doc_{rng.randint(1000, 9999)}.docx",
                   sensitivity_level=rng.choice(sens_choices), is_usb=usb) for i in range(n)]


def _own_pc(b: UserBaseline) -> str:
    return b.known_devices[0] if b.known_devices else "PC-0000"


def _usb_exfil(rng, b: UserBaseline) -> List[dict]:
    day = _session_day(rng)
    hour = (b.login_hour_mean + rng.uniform(9, 13)) % 24  # far from the user's normal hours
    if 8 <= hour < 18:
        hour = rng.choice([1, 2, 3, 22, 23])
    t0, pc, u = _at_hour(day, hour), _own_pc(b), b.user_id
    n = int(max(b.daily_file_access_mean * 4, 25) + rng.randint(5, 20))
    ev = [_event(t0, u, pc, "logon", "system", "logon", f"session://{u}@{pc}"),
          _event(t0 + timedelta(minutes=1), u, pc, "device_connect", "device", "connect", "USB_DEVICE",
                 is_usb=True, device_type="usb_storage", first_time_device=True)]
    ev += _files(rng, t0, u, pc, n, [1, 2, 2], usb=True)
    ev.append(_event(t0 + timedelta(minutes=40), u, pc, "http_request", "web", "upload",
                     "https://wikileaks.org/upload", domain="wikileaks.org", url="https://wikileaks.org/upload"))
    ev.append(_event(t0 + timedelta(minutes=55), u, pc, "logoff", "system", "logoff", f"session://{u}@{pc}"))
    return ev


def _jobhunt(rng, b: UserBaseline) -> List[dict]:
    day = _session_day(rng)
    t0, pc, u = _at_hour(day, min(max(b.login_hour_mean, 8), 16)), _own_pc(b), b.user_id
    ev = [_event(t0, u, pc, "logon", "system", "logon", f"session://{u}@{pc}")]
    for i, dom in enumerate(["linkedin.com", "indeed.com", "monster.com"]):
        ev.append(_event(t0 + timedelta(minutes=5 + i * 7), u, pc, "http_request", "web", "browse",
                         f"https://www.{dom}/jobs", domain=dom))
    ev.append(_event(t0 + timedelta(minutes=30), u, pc, "email_sent", "email", "send", "recruiter@competitor.example",
                     is_external=True, recipient_count=1))
    ev.append(_event(t0 + timedelta(minutes=45), u, pc, "device_connect", "device", "connect", "USB_DEVICE",
                     is_usb=True, device_type="usb_storage", first_time_device=False))
    n = int(max(b.daily_file_access_mean * 3, 15) + rng.randint(5, 15))
    ev += _files(rng, t0 + timedelta(minutes=45), u, pc, n, [1, 1, 2], usb=True)
    ev.append(_event(t0 + timedelta(minutes=110), u, pc, "logoff", "system", "logoff", f"session://{u}@{pc}"))
    return ev


def _keylogger(rng, b: UserBaseline) -> List[dict]:
    day = _session_day(rng)
    pc, u = f"PC-{rng.randint(1000, 9999)}", b.user_id  # the supervisor's machine, not a known device
    t0 = _at_hour(day, rng.choice([19, 20, 21]))
    ev = [_event(t0, u, pc, "logon", "system", "logon", f"session://{u}@{pc}"),
          _event(t0 + timedelta(minutes=3), u, pc, "device_connect", "device", "connect", "USB_DEVICE",
                 is_usb=True, device_type="usb_storage", first_time_device=True),
          _event(t0 + timedelta(minutes=5), u, pc, "file_access", "file", "write", "C:\\Windows\\Temp\\kl.exe",
                 sensitivity_level=2, is_usb=True)]
    for i in range(rng.randint(15, 30)):
        ev.append(_event(t0 + timedelta(minutes=20 + i), u, pc, "email_sent", "email", "send",
                         f"all-staff-{i}@dtaa.com", is_external=False, recipient_count=50))
    ev.append(_event(t0 + timedelta(minutes=60), u, pc, "logoff", "system", "logoff", f"session://{u}@{pc}"))
    return ev


def _bulk_download(rng, b: UserBaseline) -> List[dict]:
    day = _session_day(rng)
    t0, pc, u = _at_hour(day, min(max(b.login_hour_mean, 9), 15)), _own_pc(b), b.user_id
    n = int(max(b.daily_file_access_mean + 10 * max(b.daily_file_access_std, 1), 40))
    ev = [_event(t0, u, pc, "logon", "system", "logon", f"session://{u}@{pc}")]
    ev += _files(rng, t0, u, pc, n, [max(b.role_sensitivity_ceiling + 1, 2)])
    ev.append(_event(t0 + timedelta(minutes=90), u, pc, "logoff", "system", "logoff", f"session://{u}@{pc}"))
    return ev


def _benign(rng, b: UserBaseline) -> List[dict]:
    day = _session_day(rng)
    t0 = _at_hour(day, b.login_hour_mean + rng.uniform(-0.5, 0.5))
    pc, u = _own_pc(b), b.user_id
    n = max(int(round(b.daily_file_access_mean)), 0)
    ev = [_event(t0, u, pc, "logon", "system", "logon", f"session://{u}@{pc}")]
    ev += _files(rng, t0, u, pc, n, [0, max(b.typical_max_sensitivity, 0)])
    for i in range(max(int(round(b.daily_email_mean)), 0)):
        ev.append(_event(t0 + timedelta(minutes=10 + i * 5), u, pc, "email_sent", "email", "send",
                         f"colleague{i}@dtaa.com", is_external=False))
    ev.append(_event(t0 + timedelta(minutes=rng.randint(240, 480)), u, pc, "logoff", "system", "logoff",
                     f"session://{u}@{pc}"))
    return ev


def _conn(ts, src, dst, sport, dport, proto, sent, recv) -> dict:
    return _event(ts, "network", "EDGE-SENSOR-01", "network_connection", "network", "connect", f"{dst}:{dport}",
                  src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=proto,
                  bytes_sent=sent, bytes_received=recv)


def _dns_amp(rng, now) -> List[dict]:
    # Flow records as seen at the edge: small spoofed queries "from" the victim to open
    # resolvers on UDP/53, each answered with a ~50x larger response that floods the victim.
    victim = f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
    resolvers = [f"198.51.100.{rng.randint(2, 250)}" for _ in range(3)]
    return [_conn(now + timedelta(seconds=i * 0.2), victim, rng.choice(resolvers), rng.randint(1024, 65000), 53,
                  "UDP", rng.randint(60, 80), rng.randint(3000, 4000)) for i in range(25)]


def _syn_flood(rng, now) -> List[dict]:
    target = f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}"
    return [_conn(now + timedelta(seconds=i * 0.05), f"203.0.113.{rng.randint(2, 250)}", target,
                  rng.randint(1024, 65000), 443, "TCP", 60, 0) for i in range(25)]


def _port_scan(rng, now) -> List[dict]:
    src, target = f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}", f"10.0.0.{rng.randint(2, 250)}"
    ports = rng.sample([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900,
                        6379, 8080, 8443, 9200], 22)
    return [_conn(now + timedelta(seconds=i * 0.1), src, target, rng.randint(40000, 60000), p, "TCP", 60, 0 if
                  rng.random() < 0.8 else 40) for i, p in enumerate(ports)]


BEHAVIOR_GENERATORS: Dict[str, Callable] = {
    "usb_exfil_wikileaks": _usb_exfil, "jobhunt_usb_theft": _jobhunt, "keylogger_impersonation": _keylogger,
    "bulk_sensitive_download": _bulk_download, "benign_workday": _benign,
}
NETWORK_GENERATORS: Dict[str, Callable] = {
    "dns_amplification": _dns_amp, "syn_flood": _syn_flood, "port_scan": _port_scan,
}
