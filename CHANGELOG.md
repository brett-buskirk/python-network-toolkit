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
- Unified `netk` CLI (`network_toolkit/cli.py`) exposing every tool as a subcommand — `netk sniff`,
  `netk nc`, `netk tcp-server`, `netk tcp-client`, `netk tcp-proxy`, `netk udp-client`,
  `netk ssh-server`, `netk ssh-client`, `netk ssh-revshell` — with `network_packet_sniffer` wired in
  as `netk sniff` instead of only being reachable via its own `netsniff` script (which still works
  standalone).

### Changed
- Unified every tool under a single `src/` layout with valid module names (`ssh-cmd.py` →
  `network_toolkit/ssh/client.py`, etc.); `network_packet_sniffer` folded in alongside the new
  `network_toolkit` package instead of living in its own repo-within-a-repo.
- Per-tool READMEs moved to `docs/`; root `LICENSE` deduplicated (dropped the `packet-sniffer/` copy).
- Extracted a shared `network_toolkit.common` module (`create_tcp_listener`, `create_tcp_client`,
  `format_hex_dump`) and adopted it in `netcat.py`, `tcp/{server,client,proxy}.py`, and `ssh/server.py`,
  removing duplicated socket setup/teardown code from each. `network_packet_sniffer/output.py`'s
  `format_hex_dump` now delegates to the same shared function (its own tests are unaffected — same
  name, same module, same behavior). `tcp-proxy.py`'s own hand-rolled hex dump is retired in favor of
  the shared, already-tested formatter (a minor, harmless output-formatting change: lowercase hex
  offsets instead of uppercase).

### Fixed
- Repaired real bugs found while verifying each tool actually runs: two scripts
  (`ssh/client/ssh-cmd.py`, `ssh/reverse-shell/ssh-rcmd.py`) had syntax errors and couldn't even be
  parsed; `ssh/server/ssh-server.py` had a typo'd `__init__`, a nonexistent `socket.SQL_SOCKET`
  attribute, and instantiated the wrong object; `tcp/proxy/tcp-proxy.py` had a misspelled function
  definition and an unbound-variable bug on one code path.
- `tcp-server.py` and `tcp-proxy.py` now set `SO_REUSEADDR` on their listening sockets (via the shared
  `create_tcp_listener`), fixing "Address already in use" on a quick restart -- they were the only two
  listener tools that lacked it.

### Removed
- Cruft: a stray `tcp/client/.gitattributes`, scattered per-tool `requirements.txt` files, and
  `packet-sniffer`'s own `pyproject.toml`/`setup.py`/`LICENSE`/pre-refactor `sniffer.py` (fully
  superseded by its `src/` package).

_Nothing released yet — this is a raw consolidation being brought up to `v1.0.0` release quality.
See the [Roadmap](ROADMAP.md) for the phased plan._
