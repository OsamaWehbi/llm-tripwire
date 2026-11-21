# Security Policy

llm-tripwire is a detection tool, so its own behaviour matters. This document explains how to report a
vulnerability and what each command does.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/OsamaWehbi/llm-tripwire/security/advisories/new) on this
repository. You can expect an acknowledgement within 72 hours.

Useful reports include: a way to crash or hang the scanner or the callback server with crafted input, a way to make
the server do more than log and answer, or a reliable way to leak a canary past the detector that is not listed
under known limitations in the README.

## What each command does

| Command | Reads | Writes | Network |
| --- | --- | --- | --- |
| `mint` | the registry | the registry, and the decoy file for `doc` | none |
| `list`, `revoke` | the registry | the registry (`revoke`) | none |
| `scan` | the files you name (symlinks inside folders are not followed; files over 50 MB and binary files are skipped) | stdout | none |
| `watch` | the file you name | `--log`, if given | POST to `--webhook`, if given |
| `serve` | the registry, at start | `--log` | listens on `--host:--port` (127.0.0.1 by default); POST to `--webhook`, if given |

Canary values are random and created with Python's `secrets` module. Fake keys use a `twk_` prefix that no real
provider issues, so they cannot be mistaken for real credentials and grant no access anywhere.

## Callback server hardening

- It only answers `/t/<ID>` for IDs in the registry and `/healthz`. Everything else gets a 404 and is not logged.
- It never echoes request data back. Every logged field is truncated to 500 characters and written as ASCII-escaped
  JSON, so a hostile request cannot inject log lines or terminal escape sequences.
- POST bodies are read up to 64 KB. Query parameters are capped at 50 per request.
- It is a small standard-library server meant to sit behind a reverse proxy that terminates TLS and applies rate
  limits. Do not expose it directly to the internet.

## Handling the registry and logs

- The registry holds every canary value. Anyone who can read it can avoid your canaries, so keep it out of the
  systems you protect and out of public repositories. On Linux and macOS it is written with mode 600.
- Hit logs contain client addresses and whatever an attacker put in the query string or body, which may include data
  they exfiltrated. Treat them as sensitive.
- Webhooks receive a summary and the full event. Only use receivers you trust.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
