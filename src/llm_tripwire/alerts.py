"""Where hits go: stderr, a JSON Lines log and an optional webhook."""

from __future__ import annotations

import json
import sys
import threading
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

WEBHOOK_TIMEOUT = 5.0


def check_webhook(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise ValueError("webhook must be an http(s) URL")
    return url


class Alerter:
    """Thread-safe sink for events. Webhook posts run in the background so they never slow the caller."""

    def __init__(self, log: Path | None = None, webhook: str | None = None, quiet: bool = False) -> None:
        self.log = log
        self.webhook = check_webhook(webhook) if webhook else None
        self.quiet = quiet
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any], summary: str) -> None:
        record = {"time": datetime.now(UTC).isoformat(timespec="seconds"), **event}
        line = json.dumps(record, ensure_ascii=True, sort_keys=True)
        with self._lock:
            if self.log is not None:
                with self.log.open("a", encoding="utf-8", newline="\n") as f:
                    f.write(line + "\n")
            if not self.quiet:
                sys.stderr.write(f"llm-tripwire: {summary}\n")
                sys.stderr.flush()
        if self.webhook:
            threading.Thread(target=self._post, args=(summary, record), daemon=True).start()

    def _post(self, summary: str, record: dict[str, Any]) -> None:
        # "text" is read by Slack and Mattermost, "content" by Discord; other receivers get the full event.
        body = json.dumps({"text": f"llm-tripwire: {summary}", "content": f"llm-tripwire: {summary}", "event": record})
        request = urllib.request.Request(  # noqa: S310 - scheme checked in check_webhook
            self.webhook or "",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "llm-tripwire"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT):  # noqa: S310  # nosec B310
                pass
        except OSError as exc:
            sys.stderr.write(f"llm-tripwire: webhook failed: {type(exc).__name__}\n")
