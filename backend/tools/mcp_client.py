"""
MCP client used by the agents.

Two transports, same tools (tools/mcp_server.py), chosen in config.yaml › mcp.transport:

* ``inprocess`` (default) – calls the very same tool functions in the current
  thread, with pydantic argument validation (same signature the MCP schema is
  generated from). No subprocess, no event loop — fast, and safe for Django ORM.
* ``stdio`` – spawns ``python -m tools.mcp_server`` and speaks the real MCP protocol
  over stdin/stdout (what an external MCP client such as Claude Desktop would do).

Every call is timed and failures are returned as ``{"error": ...}`` — a tool
problem degrades an agent's context, it never crashes the pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import get_config

logger = logging.getLogger("soc.mcp")
BACKEND_DIR = Path(__file__).resolve().parents[1]


def _run(coro):
    """Run a coroutine from sync code, even if an event loop is already running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    box: Dict[str, Any] = {}

    def runner():
        try:
            box["value"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - re-raised below
            box["error"] = exc

    t = threading.Thread(target=runner)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


def _content_to_python(result: Any) -> Any:
    """Normalise FastMCP/ClientSession results to plain Python data."""
    if isinstance(result, tuple):  # (content, structured) in some mcp versions
        result = result[0]
    content = getattr(result, "content", result)
    if getattr(result, "isError", False):
        text = " ".join(getattr(c, "text", "") for c in content or [])
        return {"error": text or "tool error"}
    texts = [getattr(c, "text", None) for c in (content or [])]
    texts = [t for t in texts if t is not None]
    if not texts:
        return {}
    joined = texts[0] if len(texts) == 1 else "[" + ",".join(texts) + "]"
    try:
        return json.loads(joined)
    except json.JSONDecodeError:
        return {"text": joined}


class ToolClient:
    def __init__(self, transport: Optional[str] = None, timeout: Optional[float] = None):
        cfg = get_config()
        self.transport = transport or cfg.mcp.transport
        self.timeout = timeout or cfg.mcp.timeout_seconds
        self.calls: List[dict] = []  # per-instance trace (agents attach it to their output)

    # ── public ────────────────────────────────────────────────────────────
    def call(self, name: str, arguments: Optional[dict] = None) -> Any:
        arguments = arguments or {}
        start = time.perf_counter()
        try:
            if self.transport == "stdio":
                result = _run(asyncio.wait_for(self._call_stdio(name, arguments), self.timeout))
            else:
                result = self._call_inprocess(name, arguments)
            ok = not (isinstance(result, dict) and "error" in result and len(result) == 1)
        except asyncio.TimeoutError:
            result, ok = {"error": f"tool '{name}' timed out after {self.timeout}s"}, False
        except Exception as exc:
            result, ok = {"error": f"{type(exc).__name__}: {exc}"}, False
        elapsed = int((time.perf_counter() - start) * 1000)
        self.calls.append({"tool": name, "ok": ok, "ms": elapsed, "transport": self.transport})
        if not ok:
            logger.warning("MCP tool call failed", extra={"tool": name, "error": str(result)[:200]})
        return result

    def list_tools(self) -> List[dict]:
        try:
            if self.transport == "stdio":
                return _run(self._list_stdio())
            from tools.mcp_server import mcp

            return [{"name": t.name, "description": t.description} for t in _run(mcp.list_tools())]
        except Exception as exc:
            logger.warning("MCP list_tools failed", extra={"error": str(exc)})
            return []

    # ── transports ────────────────────────────────────────────────────────
    @staticmethod
    def _call_inprocess(name: str, arguments: dict) -> Any:
        from pydantic import ValidationError, validate_call

        from tools.mcp_server import TOOL_FUNCTIONS

        fn = TOOL_FUNCTIONS.get(name)
        if fn is None:
            return {"error": f"unknown tool '{name}'"}
        try:
            return validate_call(fn)(**arguments)
        except ValidationError as exc:
            return {"error": f"invalid arguments for {name}: {exc.errors()[0].get('msg')}"}

    def _server_params(self):
        from mcp import StdioServerParameters

        # pass our environment through (the SDK default only forwards a minimal set of variables)
        return StdioServerParameters(command=sys.executable, args=["-m", "tools.mcp_server"],
                                     cwd=str(BACKEND_DIR), env=dict(os.environ))

    async def _call_stdio(self, name: str, arguments: dict) -> Any:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        async with stdio_client(self._server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return _content_to_python(await session.call_tool(name, arguments))

    async def _list_stdio(self) -> List[dict]:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        async with stdio_client(self._server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                return [{"name": t.name, "description": t.description} for t in tools.tools]
