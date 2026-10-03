"""Shared fixtures."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.config import get_config


@pytest.fixture
def cfg():
    return get_config()


@pytest.fixture
def api(client):
    """Django test client that speaks JSON."""
    class JSONClient:
        def get(self, path, **params):
            return client.get(f"/api/v1{path}", params)

        def post(self, path, body=None, **headers):
            return client.post(f"/api/v1{path}", json.dumps(body or {}), content_type="application/json", **headers)

        def patch(self, path, body=None):
            return client.patch(f"/api/v1{path}", json.dumps(body or {}), content_type="application/json")

    return JSONClient()


class FakeLLMServer:
    """A tiny local HTTP server that imitates the Ollama and OpenAI-compatible APIs."""

    def __init__(self, reply="The model flagged USB use.", models=("qwen3:8b",), status=200, require_key=None):
        self.reply, self.models, self.status, self.require_key = reply, list(models), status, require_key
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def _send(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self):
                return outer.require_key is None or self.headers.get("Authorization") == f"Bearer {outer.require_key}"

            def do_GET(self):
                if self.path == "/api/tags":
                    return self._send(200, {"models": [{"name": m} for m in outer.models]})
                if self.path.endswith("/models"):
                    if not self._authorized():
                        return self._send(401, {"error": "bad key"})
                    return self._send(200, {"data": [{"id": m} for m in outer.models]})
                self._send(404, {})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append({"path": self.path, "payload": payload,
                                       "auth": self.headers.get("Authorization")})
                if outer.status != 200:
                    return self._send(outer.status, {"error": "simulated failure"})
                if self.path == "/api/chat":
                    if payload.get("model") not in outer.models:
                        return self._send(404, {"error": "model not found"})
                    return self._send(200, {"message": {"role": "assistant", "content": outer.reply}, "done": True})
                if self.path.endswith("/chat/completions"):
                    if not self._authorized():
                        return self._send(401, {"error": "bad key"})
                    return self._send(200, {"choices": [{"message": {"role": "assistant", "content": outer.reply}}]})
                self._send(404, {})

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def fake_llm_server():
    servers = []

    def make(**kwargs):
        s = FakeLLMServer(**kwargs)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()
