"""Callback server for URL canaries.

`llm-tripwire serve` answers requests to /t/<ID>, the path every URL canary uses, and records who asked: the time,
method, user agent, referrer, client address and the query string. The query string matters: Markdown-image
exfiltration puts the stolen data there. Image requests get a 1x1 transparent GIF, so a chat client that renders
the image shows nothing unusual.

The server binds to 127.0.0.1 by default. Expose it through your own reverse proxy with TLS.
"""

from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from llm_tripwire.alerts import Alerter
from llm_tripwire.registry import Registry
from llm_tripwire.tokens import ALPHABET, ID_LENGTH

PIXEL = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
MAX_BODY = 64 * 1024
MAX_FIELD = 500


def _clip(value: str) -> str:
    return value if len(value) <= MAX_FIELD else value[:MAX_FIELD] + "...(truncated)"


def canary_id_from_path(path: str) -> str | None:
    """'/t/7Q3KX2M9PA', '/t/7q3kx2m9pa.png' or '/t/7Q3KX2M9PA/anything' -> '7Q3KX2M9PA'."""
    parts = path.split("/")
    if len(parts) < 3 or parts[1] != "t":
        return None
    candidate = parts[2].split(".", 1)[0].upper()
    if len(candidate) == ID_LENGTH and all(c in ALPHABET for c in candidate):
        return candidate
    return None


def make_handler(registry: Registry, alerter: Alerter) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "httpd"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            return  # every hit is logged through the Alerter instead

        def _body(self) -> str:
            try:
                length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            except ValueError:
                length = 0
            return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

        def _handle(self, send_body: bool = True) -> None:
            split = urlsplit(self.path)
            if split.path == "/healthz":
                self._respond(200, b"ok\n", "text/plain", send_body)
                return
            canary_id = canary_id_from_path(split.path)
            canary = registry.get(canary_id) if canary_id else None
            body = self._body() if self.command == "POST" else ""
            if canary is None:
                self._respond(404, b"not found\n", "text/plain", send_body)
                return
            event = {
                "event": "url_hit",
                "canary_id": canary.id,
                "label": canary.label,
                "kind": str(canary.kind),
                "active": canary.active,
                "method": self.command,
                "path": _clip(split.path),
                "query": [[_clip(k), _clip(v)] for k, v in parse_qsl(split.query, keep_blank_values=True)][:50],
                "client": self.client_address[0],
                "forwarded_for": _clip(self.headers.get("X-Forwarded-For", "")),
                "user_agent": _clip(self.headers.get("User-Agent", "")),
                "referer": _clip(self.headers.get("Referer", "")),
                "body": _clip(body),
            }
            note = " with query data" if split.query else ""
            alerter.emit(event, f"URL canary {canary.id} ({canary.label or canary.kind}) requested{note}")
            self._respond(200, PIXEL, "image/gif", send_body)

        def _respond(self, status: int, payload: bytes, content_type: str, send_body: bool) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if send_body:
                self.wfile.write(payload)

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle(send_body=False)

    return Handler


def make_server(registry: Registry, alerter: Alerter, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(registry, alerter))
    server.daemon_threads = True
    return server
