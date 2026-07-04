# Roadmap

Phased toward a `pipx`-installable **`netk`** CLI that exposes every tool. Each phase maps to a
version [milestone](https://github.com/brett-buskirk/python-network-toolkit/milestones); ship it in
independently-useful slices (one or more PRs per phase). Full context in [`CLAUDE.md`](CLAUDE.md).

## v0.1.0 — Structure & naming
- [ ] Fix import-invalid module names (`ssh-cmd.py` → `ssh_cmd.py`, `tcp-client.py` → `tcp_client.py`, …)
- [ ] Unify a single `src/` layout across all tools (packet-sniffer is the model)
- [ ] One root `pyproject.toml` (build + `ruff` + `pytest`)
- [ ] Dedupe the LICENSE (root + `packet-sniffer/`)
- [ ] Drop cruft — stray `.gitattributes`, scattered `requirements.txt`

## v0.2.0 — Unified CLI
- [ ] A `netk` entry point with a subcommand per tool (`netk sniff`, `netk nc`, `netk tcp-server`, …)
- [ ] Fold the packet-sniffer package in as a module/subcommand, not a repo-within-a-repo

## v0.3.0 — Shared library
- [ ] Extract the real overlap — socket setup/teardown, argument parsing, hexdump/output formatting,
      framing — into a shared library so each tool is thin

## v0.4.0 — Tests & quality
- [ ] `pytest` coverage for every tool (extend packet-sniffer's suite)
- [ ] `ruff` + `mypy` clean

## v0.5.0 — CI & docs
- [ ] CI gate: lint → typecheck → test, alongside the existing AgentGate workflow
- [ ] One consolidated README with per-tool usage (per-tool docs folded into a section each)

## v1.0.0 — Release
- [ ] `pipx`-installable, tagged `v1.0.0`, Definition of Done met

---

_Security note: the SSH server / reverse-shell tools are educational — keep them clearly labeled as
such (see [`CLAUDE.md`](CLAUDE.md))._
