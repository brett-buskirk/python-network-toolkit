# Changelog

All notable changes to the Python Network Toolkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Consolidated nine standalone Python networking repos into one toolkit — packet sniffer, netcat,
  TCP server/client/proxy, UDP client, and SSH server/client/reverse-shell.
- Estate conventions: AgentGate PR guardrails, branch-protection ruleset, label taxonomy, version
  milestones (`v0.1.0`–`v1.0.0`), and a build handoff ([`CLAUDE.md`](CLAUDE.md)).
- One root `pyproject.toml` covering the whole toolkit (build + `ruff` + `pytest`).

### Changed
- Unified every tool under a single `src/` layout with valid module names (`ssh-cmd.py` →
  `network_toolkit/ssh/client.py`, etc.); `network_packet_sniffer` folded in alongside the new
  `network_toolkit` package instead of living in its own repo-within-a-repo.
- Per-tool READMEs moved to `docs/`; root `LICENSE` deduplicated (dropped the `packet-sniffer/` copy).

### Fixed
- Repaired real bugs found while verifying each tool actually runs: two scripts
  (`ssh/client/ssh-cmd.py`, `ssh/reverse-shell/ssh-rcmd.py`) had syntax errors and couldn't even be
  parsed; `ssh/server/ssh-server.py` had a typo'd `__init__`, a nonexistent `socket.SQL_SOCKET`
  attribute, and instantiated the wrong object; `tcp/proxy/tcp-proxy.py` had a misspelled function
  definition and an unbound-variable bug on one code path.

### Removed
- Cruft: a stray `tcp/client/.gitattributes`, scattered per-tool `requirements.txt` files, and
  `packet-sniffer`'s own `pyproject.toml`/`setup.py`/`LICENSE`/pre-refactor `sniffer.py` (fully
  superseded by its `src/` package).

_Nothing released yet — this is a raw consolidation being restructured into an installable `netk`
CLI. See the [Roadmap](ROADMAP.md) for the phased plan toward `v1.0.0`._
