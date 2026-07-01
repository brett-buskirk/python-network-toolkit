# Python Network Toolkit — Claude Code Build Brief
### Turn a raw merge of nine networking repos into one cohesive, installable toolkit

> This repo was assembled by merging nine standalone Python networking repos into subdirectories.
> It works, but it's a **raw consolidation** — inconsistent structure, loose scripts, import-invalid
> module names, and scattered packaging. This file is the repo's `CLAUDE.md` **and** the brief for
> the agent cleaning it up. Read it top to bottom before touching anything.

---

## What it is

A hands-on collection of small Python networking tools — a packet sniffer, a netcat clone, TCP
server/client/proxy, a UDP client, and SSH server/client/reverse-shell. It's a **portfolio piece**
demonstrating networking fundamentals (sockets, protocols, SSH), so the finished repo should read
as a deliberate, well-built toolkit — not a folder of exercises.

## The mission

**Consolidate → cohere → professionalize.** The nine tools currently sit side by side with no shared
structure. Turn them into one well-structured, tested, installable Python toolkit worth showing a
client. Ship it in independently-useful slices (see the phased plan); each phase is one or more PRs.

## Current state (the raw merge)

- **`packet-sniffer/`** — already a *proper package*: `src/network_packet_sniffer/` layout,
  `pyproject.toml`, `setup.py`, and a real `tests/` suite. **This is the model** to bring the rest up to.
- **The other 8** — loose single-file scripts with **hyphenated, import-invalid names**
  (`ssh-cmd.py`, `tcp-client.py`, `udp-client.py`, …), each with its own README and, sometimes, its
  own `requirements.txt`:
  - `netcat/netcat.py`
  - `tcp/{server,client,proxy}/*.py`
  - `udp/client/udp-client.py`
  - `ssh/{server,client,reverse-shell}/*.py`
- **Cruft:** duplicate `LICENSE` (root + `packet-sniffer/`), a stray `.gitattributes` under `tcp/client/`,
  no root packaging, no unified CLI, no top-level tests / lint / CI.

## Target state

- **One installable package with a unified CLI** — recommend a single entry point (e.g. `netk`)
  exposing subcommands: `netk sniff`, `netk nc`, `netk tcp-server`, `netk tcp-proxy`,
  `netk ssh-server`, `netk ssh-client`, `netk ssh-revshell`, `netk udp-client`. Fold the existing
  packet-sniffer package in as a module/subcommand rather than leaving it a repo-within-a-repo.
  *(If a unified CLI proves awkward, the fallback is a consistent package-per-tool layout — but
  decide once and apply everywhere.)*
- **Valid Python module names throughout** (`ssh_cmd.py`, not `ssh-cmd.py`) and a coherent `src/` layout.
- **A shared library** for the real overlap — socket setup/teardown, argument parsing, hexdump/output
  formatting, framing — so each tool is thin.
- **One root `pyproject.toml`** (build + `ruff` + `pytest`), consolidating the scattered `requirements.txt`.
- **Tests for every tool** (extend packet-sniffer's pattern); **`ruff` + `mypy` clean**.
- **A CI gate** (lint → typecheck → test) alongside the existing AgentGate workflow.
- **One clean root README** (per-tool docs folded into a section each), a **single** LICENSE, no cruft.

## Working conventions (non-negotiable)

- **No direct commits to `main`.** Branch → PR (`gh pr create`) → green checks → merge. Self-merge ok.
  Assign `brett-buskirk` to issues/PRs. See `CONTRIBUTING.md`.
- **AgentGate runs on every PR** (`.agentgate.yml`: `secrets`/`dangerous_patterns` block, `scope`
  advisory). A restructuring PR will trip non-blocking warnings — expected.
- **Never commit secrets** — SSH keys, `.env`, `*.pem`/`*.key` are gitignored.
- **Security note:** the SSH server / reverse-shell tools are educational. Keep them clearly labeled as
  such; don't add anything that reads as offensive tooling.

## Phased plan (each phase → a milestone)

- **v0.1.0 — Structure & naming.** Fix module names, unify the `src/` layout, add one root
  `pyproject.toml`, dedupe the LICENSE, drop cruft.
- **v0.2.0 — Unified CLI.** A `netk` entry point with a subcommand per tool; packet-sniffer folded in.
- **v0.3.0 — Shared library.** Extract common socket/output/arg helpers; make each tool thin.
- **v0.4.0 — Tests & quality.** `pytest` coverage for every tool; `ruff` + `mypy` clean.
- **v0.5.0 — CI & docs.** lint/typecheck/test CI gate; consolidated README with per-tool usage.
- **v1.0.0 — Release.** `pipx`-installable, tagged `v1.0.0`, DoD met.

## Definition of Done

`pipx install .` yields a working `netk` CLI exposing every tool; consistent structure and valid
module names throughout; `pytest` + `ruff` + `mypy` green in CI; one clean README; a single MIT
LICENSE. AgentGate green on the final PR.

## Reference repos

- **`~/github-repos/agent-gate`** — conventions model (docs suite, CI gate, CHANGELOG/ROADMAP,
  label taxonomy, milestone-per-version).
- **`~/github-repos/repo-conventions`** — the estate-wide setup standard.
