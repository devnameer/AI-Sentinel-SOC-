"""MCP tools: allow-listed, read-only, both transports."""
import os
import platform

import pytest

from tools.collectors import COLLECTORS, run_collector
from tools.mcp_client import ToolClient

pytestmark = pytest.mark.django_db


def test_tool_catalogue_has_no_code_execution():
    names = {t["name"] for t in ToolClient(transport="inprocess").list_tools()}
    assert {"collect_host_events", "get_user_baseline", "explain_rules", "search_knowledge",
            "get_user_incident_history", "get_risk_policy", "list_collectors"} == names
    assert not any("exec" in n or "python" in n or "shell" in n for n in names)


def test_inprocess_calls_and_validation():
    c = ToolClient(transport="inprocess")
    assert c.call("get_user_baseline", {"user_id": "AAM0658"})["department"]
    assert "usb_first_time" in c.call("explain_rules", {"rule_ids": ["usb_first_time"]})
    assert "error" in c.call("explain_rules", {"rule_ids": "not-a-list"})
    assert "error" in c.call("no_such_tool", {})
    assert c.call("get_user_incident_history", {"user_id": "nobody"})["analyses"] == 0
    assert [x["ok"] for x in c.calls] == [True, True, False, False, True]


def test_knowledge_search_returns_relevant_chunk():
    hits = ToolClient().call("search_knowledge", {"query": "USB exfiltration wikileaks after hours", "k": 2})
    assert hits["results"] and "USB" in hits["results"][0]["text"]


def test_collectors_are_allow_listed():
    out = ToolClient().call("collect_host_events", {"collectors": ["system", "rm -rf"], "max_events": 20})
    by_name = {r["collector"]: r for r in out["results"]}
    assert by_name["rm -rf"]["ok"] is False and "allow-list" in by_name["rm -rf"]["error"]
    assert by_name["system"]["ok"] is True and out["total"] >= 1


@pytest.mark.parametrize("name", ["system", "process", "network"])
def test_cross_platform_collectors_run(name):
    r = run_collector(name, max_events=50)
    assert r["ok"], r.get("error")
    for e in r["events"]:
        assert {"timestamp", "user_id", "device_id", "event_type"} <= set(e)


def test_windows_only_collectors_report_cleanly():
    if platform.system() == "Windows":
        pytest.skip("running on Windows")
    r = run_collector("registry")
    assert r["ok"] is False and "only runs on Windows" in r["error"]
    assert set(COLLECTORS) >= {"system", "process", "network", "file", "usb", "registry"}


@pytest.mark.skipif(os.environ.get("SKIP_STDIO_MCP") == "1", reason="stdio transport test disabled")
def test_stdio_transport_speaks_real_mcp():
    c = ToolClient(transport="stdio", timeout=60)
    assert "usb_first_time" in c.call("explain_rules", {"rule_ids": ["usb_first_time"]})
    assert c.calls[-1]["transport"] == "stdio" and c.calls[-1]["ok"]
