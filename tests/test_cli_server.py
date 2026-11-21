import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from llm_tripwire import Canary, Kind, Registry, __version__
from llm_tripwire.alerts import Alerter, check_webhook
from llm_tripwire.cli import app
from llm_tripwire.server import PIXEL, canary_id_from_path, make_server

ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()
CID = "7QK3XM9PAE"


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LLM_TRIPWIRE_REGISTRY", raising=False)
    return tmp_path


def registry(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["canaries"]


def test_version():
    assert runner.invoke(app, ["--version"]).output.strip() == f"llm-tripwire {__version__}"


def test_mint_each_kind(workdir):
    assert runner.invoke(app, ["mint", "phrase", "-l", "prompt"]).exit_code == 0
    assert runner.invoke(app, ["mint", "key"]).exit_code == 0
    assert runner.invoke(app, ["mint", "url", "--callback", "https://canary.example.com/"]).exit_code == 0
    assert runner.invoke(app, ["mint", "email", "--domain", "corp.example"]).exit_code == 0
    out = runner.invoke(app, ["mint", "doc", "--template", "memo", "--callback", "https://canary.example.com"])
    assert out.exit_code == 0
    items = registry(workdir / "tripwire.json")
    assert [c["kind"] for c in items] == ["phrase", "key", "url", "email", "doc"]
    for c in items[:4]:
        assert c["id"].lower() in c["value"].lower()
    assert items[2]["value"] == f"https://canary.example.com/t/{items[2]['id']}"
    memo = (workdir / "memo.md").read_text(encoding="utf-8")
    assert memo.count(items[4]["id"]) == 3
    assert items[4]["value"] == "memo.md"


def test_mint_errors(workdir):
    assert runner.invoke(app, ["mint", "url"]).exit_code == 2
    assert runner.invoke(app, ["mint", "email"]).exit_code == 2
    assert runner.invoke(app, ["mint", "doc", "--template", "nope"]).exit_code == 2
    assert runner.invoke(app, ["mint", "doc"]).exit_code == 0
    assert runner.invoke(app, ["mint", "doc"]).exit_code == 2  # refuses to overwrite credentials.md


def test_scan_list_revoke(workdir):
    runner.invoke(app, ["mint", "phrase"])
    cid = registry(workdir / "tripwire.json")[0]["id"]
    (workdir / "out.txt").write_text(f"leaked {' '.join(cid)}\n", encoding="utf-8")
    (workdir / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    hit = runner.invoke(app, ["scan", "out.txt", "clean.txt", "-f", "json"])
    assert hit.exit_code == 1
    assert [h["transform"] for h in json.loads(hit.output)] == ["reformatted"]
    assert runner.invoke(app, ["scan", "clean.txt"]).exit_code == 0
    assert runner.invoke(app, ["scan", "out.txt", "--no-fail"]).exit_code == 0
    assert runner.invoke(app, ["scan", "."]).exit_code == 1
    assert cid in runner.invoke(app, ["list"]).output
    assert runner.invoke(app, ["revoke", cid]).exit_code == 0
    assert runner.invoke(app, ["scan", "out.txt"]).exit_code == 0
    assert cid not in runner.invoke(app, ["list"]).output
    assert cid in runner.invoke(app, ["list", "--all"]).output
    assert runner.invoke(app, ["revoke", "ZZZZZZZZZZ"]).exit_code == 2


def test_scan_stdin_and_jsonl(workdir):
    runner.invoke(app, ["mint", "key"])
    value = registry(workdir / "tripwire.json")[0]["value"]
    out = runner.invoke(app, ["scan", "-", "-f", "jsonl"], input=f"tool output: {value}\n")
    assert out.exit_code == 1
    assert json.loads(out.output.splitlines()[0])["source"] == "stdin"


def test_registry_errors(workdir):
    assert runner.invoke(app, ["list"]).exit_code == 2  # no registry yet
    (workdir / "tripwire.json").write_text(json.dumps({"version": 9}), encoding="utf-8")
    assert runner.invoke(app, ["list"]).exit_code == 2
    (workdir / "tripwire.json").write_text(
        json.dumps({"version": 1, "canaries": [{"id": "short", "kind": "phrase", "value": "x"}]}), encoding="utf-8"
    )
    assert runner.invoke(app, ["list"]).exit_code == 2


def test_registry_env_var(workdir, monkeypatch):
    target = workdir / "elsewhere.json"
    monkeypatch.setenv("LLM_TRIPWIRE_REGISTRY", str(target))
    runner.invoke(app, ["mint", "phrase"])
    assert target.exists()
    assert not (workdir / "tripwire.json").exists()


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/t/7QK3XM9PAE", CID),
        ("/t/7qk3xm9pae.png", CID),
        ("/t/7QK3XM9PAE/x/y", CID),
        ("/t/short", None),
        ("/x/7QK3XM9PAE", None),
    ],
)
def test_canary_id_from_path(path, expected):
    assert canary_id_from_path(path) == expected


@pytest.fixture
def server(tmp_path):
    reg = Registry([Canary(id=CID, kind=Kind.url, value=f"http://x/t/{CID}", label="decoy runbook")])
    log = tmp_path / "hits.jsonl"
    srv = make_server(reg, Alerter(log=log, quiet=True), "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", log
    srv.shutdown()
    srv.server_close()


def test_server_logs_hits_and_returns_pixel(server):
    base, log = server
    request = urllib.request.Request(f"{base}/t/{CID}.png?d=summary+of+chat&x=1", headers={"User-Agent": "agent/1.0"})
    with urllib.request.urlopen(request, timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "image/gif"
        assert resp.read() == PIXEL
    post = urllib.request.Request(f"{base}/t/{CID}", data=b"exfil body", method="POST")
    with urllib.request.urlopen(post, timeout=5) as resp:
        assert resp.status == 200
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert [e["method"] for e in events] == ["GET", "POST"]
    assert events[0]["query"] == [["d", "summary of chat"], ["x", "1"]]
    assert events[0]["user_agent"] == "agent/1.0"
    assert events[0]["label"] == "decoy runbook"
    assert events[1]["body"] == "exfil body"


def test_server_unknown_paths(server):
    base, log = server
    for path in ("/t/ZZZZZZZZZZ", "/other", "/t/"):
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(base + path, timeout=5)
        assert exc.value.code == 404
    with urllib.request.urlopen(base + "/healthz", timeout=5) as resp:
        assert resp.read() == b"ok\n"
    assert not log.exists()


def test_webhook_receives_event(tmp_path):
    received = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    hook = ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=hook.serve_forever, daemon=True).start()
    try:
        alerter = Alerter(webhook=f"http://127.0.0.1:{hook.server_address[1]}/hook", quiet=True)
        alerter.emit({"event": "test"}, "canary seen")
        for _ in range(50):
            if received:
                break
            threading.Event().wait(0.1)
    finally:
        hook.shutdown()
        hook.server_close()
    assert received[0]["text"] == "llm-tripwire: canary seen"
    assert received[0]["event"]["event"] == "test"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "notaurl", "https://"])
def test_webhook_must_be_http(url):
    with pytest.raises(ValueError):
        check_webhook(url)


def _text_files():
    skip = {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for path in ROOT.rglob("*"):
        if set(path.relative_to(ROOT).parts) & skip or not path.is_file() or path.suffix == ".pyc":
            continue
        yield path


@pytest.mark.parametrize("path", list(_text_files()), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_source_files_are_ascii(path):
    assert all(b < 128 for b in path.read_bytes()), f"non-ASCII byte in {path.relative_to(ROOT)}"
