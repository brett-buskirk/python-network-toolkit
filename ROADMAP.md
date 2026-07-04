# Roadmap

Phased toward a `pipx`-installable **`netk`** CLI that exposes every tool. Each phase maps to a
version [milestone](https://github.com/brett-buskirk/python-network-toolkit/milestones); ship it in
independently-useful slices (one or more PRs per phase). Full context in [`CLAUDE.md`](CLAUDE.md).

## v0.1.0 — Structure & naming
- [x] **Verify each tool runs** and does what its README claims; **fix what's broken** (dead imports,
      Python 2-isms, deprecated APIs, wrong defaults)
- [x] Fix import-invalid module names (`ssh-cmd.py` → `ssh_cmd.py`, `tcp-client.py` → `tcp_client.py`, …)
- [x] Unify a single `src/` layout across all tools (packet-sniffer is the model)
- [x] One root `pyproject.toml` (build + `ruff` + `pytest`)
- [x] Dedupe the LICENSE (root + `packet-sniffer/`)
- [x] Drop cruft — stray `.gitattributes`, scattered `requirements.txt`

## v0.2.0 — Unified CLI
- [x] A `netk` entry point with a subcommand per tool (`netk sniff`, `netk nc`, `netk tcp-server`, …)
- [x] Fold the packet-sniffer package in as a module/subcommand, not a repo-within-a-repo

## v0.3.0 — Shared library
- [x] Extract the real overlap — socket setup/teardown (`network_toolkit.common`) and hexdump/output
      formatting (also fixed a latent `SO_REUSEADDR` inconsistency along the way) — into a shared
      library so each tool is thin
- [ ] Argument parsing / framing helpers — deferred: only one or two tools have real CLI flags today,
      so there isn't yet enough duplication to justify a shared layer. Revisit once v1.1.0 gives more
      tools real flags.

## v0.4.0 — Tests & quality
- [x] `ruff` + `mypy` clean
- [x] `pytest` coverage for `network_toolkit`'s socket-based tools (`common`, `netcat`, `tcp/*`,
      `udp/client`, the `netk` dispatcher)
- [x] `pytest` coverage for the SSH tools (`ssh/client`, `ssh/server`, `ssh/reverse_shell`)

## v0.5.0 — CI & docs
- [ ] CI gate: lint → typecheck → test, alongside the existing AgentGate workflow
- [ ] One consolidated README with per-tool usage (per-tool docs folded into a section each)

## v1.0.0 — Release
- [ ] `pipx`-installable, tagged `v1.0.0`, Definition of Done met — every tool verified working

## v1.1.0 — Expand the suite
Deepen the existing tools, then grow the collection. Candidates (pick what fits; quality over count):
- [ ] **UDP server** — fill the gap (there's a UDP client but no server)
- [ ] **Port scanner** — TCP connect / UDP, optional banner grabbing
- [ ] **Host discovery** — ARP sweep or ping sweep across a subnet
- [ ] **ICMP tools** — ping and traceroute
- [ ] **DNS query tool** — a small `dig`-style resolver (A / AAAA / MX / TXT)
- [ ] **TLS/cert inspector** — print the certificate chain and expiry
- [ ] Deepen existing tools — richer flags, output, error handling, protocol coverage

---

_Security & responsible use: every tool is educational and authorized-use only — see
[`SECURITY.md`](SECURITY.md) and [`CLAUDE.md`](CLAUDE.md)._
