"""Command-line interface: mint, list, revoke, scan, watch and serve."""

from __future__ import annotations

import json
import os
import sys
import time
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from llm_tripwire import __version__, decoy, tokens
from llm_tripwire.alerts import Alerter
from llm_tripwire.detect import Detector, Hit
from llm_tripwire.registry import Canary, Registry
from llm_tripwire.tokens import Kind

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Canary tokens for LLM applications: plant them in prompts, documents and tools, then catch leaks.",
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
MAX_FILE = 50 * 1024 * 1024


class Format(StrEnum):
    table = "table"
    json = "json"
    jsonl = "jsonl"


def _version(value: bool) -> None:
    if value:
        console.print(f"llm-tripwire {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version."),
) -> None:
    pass


RegistryOpt = typer.Option(
    None, "--registry", "-r", help="Canary registry file (default: $LLM_TRIPWIRE_REGISTRY or ./tripwire.json)."
)


def _load(path: Path | None, missing_ok: bool = False) -> Registry:
    try:
        return Registry.load(path, missing_ok=missing_ok)
    except (FileNotFoundError, ValueError) as exc:
        err.print(f"[red]error:[/] {escape(str(exc))}")
        raise typer.Exit(2) from exc


@app.command()
def mint(
    kind: Kind = typer.Argument(..., help="phrase, key, url, email or doc."),
    label: str = typer.Option("", "--label", "-l", help="Where you will plant it, e.g. 'support bot system prompt'."),
    callback: str | None = typer.Option(None, help="Base URL of your `llm-tripwire serve` endpoint (url, doc)."),
    domain: str | None = typer.Option(None, help="A mail domain you control (email)."),
    template: str = typer.Option("credentials", help=f"Decoy template for doc: {', '.join(decoy.TEMPLATES)}."),
    out: Path | None = typer.Option(None, "--out", "-o", help="Where to write the decoy document (doc)."),
    registry: Path | None = RegistryOpt,
) -> None:
    """Create a canary, record it in the registry and show how to plant it."""
    reg = _load(registry, missing_ok=True)
    try:
        minted = tokens.mint(kind, callback=callback, domain=domain)
        document = decoy.render(template, minted.id, callback) if kind is Kind.doc else None
    except ValueError as exc:
        err.print(f"[red]error:[/] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    value = minted.value
    if document is not None:
        target = out or Path(f"{template}.md")
        if target.exists():
            err.print(f"[red]error:[/] {escape(str(target))} already exists")
            raise typer.Exit(2)
        target.write_text(document, encoding="utf-8", newline="\n")
        value = str(target)
    reg.add(Canary(id=minted.id, kind=kind, value=value, label=label))
    saved = reg.save()
    console.print(f"[bold]canary {minted.id}[/] ({kind}) recorded in {escape(str(saved))}")
    if kind is not Kind.doc:
        console.print(f"[green]{escape(value)}[/]")
    console.print()
    console.print(escape(decoy.planting_advice(kind, value, minted.id)))


@app.command("list")
def list_cmd(
    show_all: bool = typer.Option(False, "--all", help="Include revoked canaries."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON."),
    registry: Path | None = RegistryOpt,
) -> None:
    """List canaries."""
    reg = _load(registry)
    items = reg.canaries if show_all else reg.active
    if as_json:
        sys.stdout.write(json.dumps([c.model_dump(mode="json") for c in items], indent=2) + "\n")
        return
    table = Table(header_style="bold")
    for col in ("ID", "Kind", "Label", "Value", "Created", "Active"):
        table.add_column(col, overflow="fold")
    for c in items:
        table.add_row(c.id, str(c.kind), escape(c.label), escape(c.value), c.created, "yes" if c.active else "no")
    console.print(table)


@app.command()
def revoke(canary_id: str = typer.Argument(..., help="The canary ID."), registry: Path | None = RegistryOpt) -> None:
    """Stop alerting on a canary, for example after removing it from where it was planted."""
    reg = _load(registry)
    canary = reg.get(canary_id)
    if canary is None:
        err.print(f"[red]error:[/] no canary {escape(canary_id)}")
        raise typer.Exit(2)
    canary.active = False
    reg.save()
    console.print(f"revoked {canary.id}")


def _iter_inputs(paths: list[str]):
    for raw in paths:
        if raw == "-":
            yield "stdin", sys.stdin.read()
            continue
        p = Path(raw)
        if p.is_dir():
            for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for name in sorted(filenames):
                    f = Path(dirpath) / name
                    if f.is_symlink():
                        continue
                    yield from _read(f)
        elif p.exists():
            yield from _read(p)
        else:
            err.print(f"[yellow]warning:[/] {escape(raw)} not found")


def _read(path: Path):
    try:
        if path.stat().st_size > MAX_FILE:
            err.print(f"[yellow]skipped (over 50 MB):[/] {escape(str(path))}")
            return
        data = path.read_bytes()
    except OSError as exc:
        err.print(f"[yellow]skipped:[/] {escape(str(path))}: {escape(type(exc).__name__)}")
        return
    if b"\x00" in data[:4096]:
        return  # binary
    yield path.as_posix(), data.decode("utf-8", errors="replace")


def _render(hits: list[Hit], fmt: Format) -> None:
    if fmt is Format.json:
        sys.stdout.write(json.dumps([h.model_dump(mode="json") for h in hits], indent=2) + "\n")
        return
    if fmt is Format.jsonl:
        for h in hits:
            sys.stdout.write(json.dumps(h.model_dump(mode="json"), ensure_ascii=True) + "\n")
        return
    if not hits:
        console.print("[green]No canaries found.[/]")
        return
    table = Table(header_style="bold")
    for col in ("Canary", "Label", "How", "Where", "Context"):
        table.add_column(col, overflow="fold")
    for h in hits:
        how = h.transform if not h.obfuscated else f"[bold red]{escape(h.transform)}[/]"
        where = f"{h.source}:{h.line}" if h.line else h.source
        table.add_row(f"{h.canary_id} ({h.kind})", escape(h.label), how, escape(where), escape(h.snippet))
    console.print(table)
    console.print(f"[bold red]{len(hits)} canary hit(s)[/]")


@app.command()
def scan(
    paths: list[str] = typer.Argument(..., help="Files, directories or - for stdin: model outputs, logs, transcripts."),
    fmt: Format = typer.Option(Format.table, "--format", "-f", help="Output format."),
    fail: bool = typer.Option(True, "--fail/--no-fail", help="Exit with status 1 when a canary is found."),
    registry: Path | None = RegistryOpt,
) -> None:
    """Look for planted canaries in text, including reformatted and encoded copies."""
    detector = Detector(_load(registry))
    hits: list[Hit] = []
    for source, text in _iter_inputs(paths):
        hits.extend(detector.scan(text, source))
    _render(hits, fmt)
    if hits and fail:
        raise typer.Exit(1)


@app.command()
def watch(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="A log file to follow, like `tail -f`."),
    log: Path | None = typer.Option(None, "--log", help="Append hits to this JSON Lines file."),
    webhook: str | None = typer.Option(None, help="POST each hit to this URL (Slack, Discord or any JSON receiver)."),
    from_start: bool = typer.Option(False, "--from-start", help="Scan the existing content first."),
    interval: float = typer.Option(1.0, help="Polling interval in seconds."),
    registry: Path | None = RegistryOpt,
) -> None:
    """Follow a log file and alert when a canary appears in it."""
    detector = Detector(_load(registry))
    try:
        alerter = Alerter(log=log, webhook=webhook)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    stream = detector.stream()
    stream.source = path.as_posix()
    err.print(f"watching {escape(str(path))} for {len(detector.by_core)} canary(ies); Ctrl+C to stop")
    with path.open("r", encoding="utf-8", errors="replace") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        try:
            while True:
                chunk = f.read(1 << 16)
                if not chunk:
                    time.sleep(interval)
                    continue
                for hit in stream.feed(chunk):
                    alerter.emit(
                        {"event": "text_hit", **hit.model_dump(mode="json")},
                        f"canary {hit.canary_id} ({hit.label or hit.kind}) found in {hit.source} [{hit.transform}]",
                    )
        except KeyboardInterrupt:
            err.print("stopped")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Address to bind. Put a TLS reverse proxy in front for public use."),
    port: int = typer.Option(8787, help="Port to listen on."),
    log: Path | None = typer.Option(Path("tripwire-hits.jsonl"), "--log", help="Append hits to this JSON Lines file."),
    webhook: str | None = typer.Option(None, help="POST each hit to this URL (Slack, Discord or any JSON receiver)."),
    registry: Path | None = RegistryOpt,
) -> None:
    """Run the callback server for URL and decoy-document canaries."""
    from llm_tripwire.server import make_server

    reg = _load(registry)
    try:
        alerter = Alerter(log=log, webhook=webhook)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    server = make_server(reg, alerter, host, port)
    err.print(f"llm-tripwire {__version__} listening on http://{host}:{server.server_address[1]}/t/<id>")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        err.print("stopped")
    finally:
        server.server_close()


def main() -> None:
    # Never crash on a console that cannot show a character from a log.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    # Click expands wildcards in arguments on Windows; paths and globs are passed through unchanged instead.
    app(windows_expand_args=False)
