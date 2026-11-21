# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `llm-tripwire mint` for five canary kinds: `phrase`, `key`, `url`, `email` and `doc` (decoy documents from the
  `credentials` and `memo` templates), with planting advice for each. Canaries are recorded in a JSON registry.
- A detector that finds canaries verbatim, reformatted (case, separators, Cyrillic and Greek look-alikes, full-width
  characters), reversed, and inside base64, hex, percent-encoding and ROT13, with one level of nesting.
- `llm-tripwire scan` for files, folders and stdin, with table, JSON and JSON Lines output and a failing exit status
  on hits.
- `llm-tripwire watch` to follow a log file, and `llm-tripwire serve`, a callback server for URL canaries that logs
  requests (including query strings and POST bodies) and answers with a transparent GIF.
- Webhook alerts compatible with Slack and Discord.
- Python API: `Detector.scan`, `Detector.redact` and a streaming scanner that finds canaries split across chunks.
- `llm-tripwire list` and `llm-tripwire revoke`.
