# Changelog

All notable changes to the Python Network Toolkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- README lacked any end-user install instructions, and the published `v1.0.0` GitHub Release notes
  incorrectly claimed `pipx install python-network-toolkit` (implying PyPI availability that doesn't
  exist). Added a proper Installation section documenting the working path — `pipx install` directly
  from this git repo — and corrected the release notes to match.

## [1.0.0] - 2026-07-04

### Added
- Consolidated nine standalone Python networking repos into one toolkit — packet sniffer, netcat,
  TCP server/client/proxy, UDP client, and SSH server/client/reverse-shell.
- Estate conventions: AgentGate PR guardrails, branch-protection ruleset, label taxonomy, version
  milestones (`v0.1.0`–`v1.0.0`), and a build handoff ([`CLAUDE.md`](CLAUDE.md)).
- One root `pyproject.toml` covering the whole toolkit (build + `ruff` + `pytest`).
- CI gate (`.github/workflows/ci.yml`) alongside the existing AgentGate workflow: a `lint` job
  (`ruff check .` + `mypy src/`) gates a `test` job running the full `pytest` suite across a
  Python 3.10/3.11/3.12 matrix, validating the multi-version support already declared in
  `pyproject.toml`'s classifiers.
- `pytest` coverage for `network_toolkit`'s socket-based tools: `common.py` (the shared socket/hexdump
  helpers), `netcat.py` (listen/send, `-c`/`-e`/`-u` modes), `tcp/{server,client,proxy}.py`,
  `udp/client.py`, and the `netk` CLI dispatcher (help/error paths and correct argv forwarding per
  subcommand). All loopback-only, no root privileges or live network required, matching
  `network_packet_sniffer`'s existing suite.
- `pytest` coverage for the SSH tools: `ssh/client.py` (a real connect + `exec_command` round trip
  against a dedicated exec-capable test server, plus `main()`'s prompt-wiring), `ssh/server.py`
  (`Server`'s auth/channel-request logic directly, plus a real paramiko client authenticating through
  it), and `ssh/reverse_shell.py` (a full controller/agent round trip against the real
  `ssh/server.py` `Server`, plus `main()`'s prompt-wiring). Uses a throwaway generated RSA host key
  per test, matching the manual verification approach used earlier in this project's history.
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
- Folded the per-tool `docs/*.md` files into one consolidated root `README.md` (a section per tool,
  with real usage examples/flags reflecting current behavior rather than the original one-line stubs
  most of them were); `docs/` is removed now that it's the single source of truth.
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
- `netk`'s `_print_usage()` captured `sys.stdout` in a default argument at import time instead of
  looking it up per call, so it silently bypassed any stdout redirection (found while adding tests for
  it).
- Fixed several pre-existing `mypy` errors in `network_packet_sniffer`: implicit-`Optional` parameters,
  and four `os.name == "nt"` checks that mypy couldn't platform-narrow (now `sys.platform == "win32"`).
- `netcat.py`'s command-shell mode (`-c`): a client that disconnected abruptly (e.g. a connection reset)
  crashed the shared listening socket for every other client, since the error handler closed
  `self.socket` instead of just that client's `client_socket`. Found while re-verifying `pipx install .`
  for the `v1.0.0` release — an automated readiness probe connecting-then-disconnecting reliably
  triggered it.

### Removed
- Cruft: a stray `tcp/client/.gitattributes`, scattered per-tool `requirements.txt` files, and
  `packet-sniffer`'s own `pyproject.toml`/`setup.py`/`LICENSE`/pre-refactor `sniffer.py` (fully
  superseded by its `src/` package).

See the [Roadmap](ROADMAP.md) for what's next past `v1.0.0`.
