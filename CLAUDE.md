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

**Consolidate → cohere → verify & improve → professionalize → grow.** The nine tools currently sit
side by side with no shared structure. Turn them into one well-structured, tested, installable Python
toolkit worth showing a client — then keep growing it. Ship in independently-useful slices (see the
phased plan); each phase is one or more PRs.

Beyond restructuring, **you own the tools themselves**, not just their packaging:

- **Verify** — actually run every tool and confirm it does what its README claims. Don't assume the
  raw merge works; scripts may be stale, half-finished, or broken.
- **Fix** — repair what's broken: dead imports, Python 2-isms, deprecated/removed APIs, wrong
  defaults, platform assumptions.
- **Expand & improve** — deepen each tool where it's thin (better flags, output, error handling,
  protocol coverage, `--help`) so it reads as a real utility, not an exercise.
- **Grow the suite** — add new tools that genuinely fit (see **Candidate additions**). Coherence and
  quality over count; every new tool follows the same structure, tests, and docs as the rest.

All of this stays **educational, authorized-use** security tooling — see [`SECURITY.md`](SECURITY.md)
and keep new work inside that framing.

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
- **Every tool verified and fixed** — each one actually runs and does what it claims.
- **Deeper, more useful tools** — thin exercises brought up to real-utility quality.
- **A growing suite** — new tools that fit the theme, added to the same standard.

## Candidate additions (grow the suite)

New tools that fit the networking-fundamentals theme. These are a starting menu, **not a mandate** —
pick what earns its place, skip what doesn't, and prefer a few polished tools over many shallow ones.
Keep everything authorized-use and covered by [`SECURITY.md`](SECURITY.md).

- **UDP server** — the obvious gap: there's a UDP client but no server (TCP has both).
- **Port scanner** — TCP connect / UDP, with optional banner grabbing.
- **Host discovery** — ARP sweep or ping sweep across a subnet.
- **ICMP tools** — ping and traceroute.
- **DNS query tool** — a small `dig`-style resolver (A / AAAA / MX / TXT).
- **TLS/cert inspector** — connect and print the certificate chain and expiry.

## Working conventions (non-negotiable)

- **No direct commits to `main`.** Branch → PR (`gh pr create`) → green checks → merge. Self-merge ok.
  Assign `brett-buskirk` to issues/PRs. See `CONTRIBUTING.md`.
- **AgentGate runs on every PR** (`.agentgate.yml`: `secrets`/`dangerous_patterns` block, `scope`
  advisory). A restructuring PR will trip non-blocking warnings — expected.
- **Never commit secrets** — SSH keys, `.env`, `*.pem`/`*.key` are gitignored.
- **Security / responsible use:** these are educational, authorized-use tools (see [`SECURITY.md`](SECURITY.md)).
  Keep every tool — existing and new — clearly framed that way: a diagnostic/learning utility used only
  on systems you own or have permission to test. Don't build anything whose primary purpose is attack,
  evasion, or covert use with no legitimate diagnostic value.

## Phased plan (each phase → a milestone)

- **v0.1.0 — Structure & naming.** Fix module names, unify the `src/` layout, add one root
  `pyproject.toml`, dedupe the LICENSE, drop cruft — and **verify each tool runs, fixing what's broken**
  as you go (you can't cleanly restructure a tool you haven't confirmed works).
- **v0.2.0 — Unified CLI.** A `netk` entry point with a subcommand per tool; packet-sniffer folded in.
- **v0.3.0 — Shared library.** Extract common socket/output/arg helpers; make each tool thin.
- **v0.4.0 — Tests & quality.** `pytest` coverage for every tool; `ruff` + `mypy` clean.
- **v0.5.0 — CI & docs.** lint/typecheck/test CI gate; consolidated README with per-tool usage.
- **v1.0.0 — Release.** `pipx`-installable, tagged `v1.0.0`, DoD met.
- **v1.1.0 — Expand the suite.** Deepen the existing tools and add new ones that fit (see **Candidate
  additions**), each to the same structure / tests / docs standard.

## Definition of Done

**v1.0.0:** `pipx install .` yields a working `netk` CLI exposing every tool; **every tool has been run
and confirmed working (or fixed)**; consistent structure and valid module names throughout; `pytest` +
`ruff` + `mypy` green in CI; one clean README; a single MIT LICENSE. AgentGate green on the final PR.

Past 1.0 the suite keeps growing (v1.1.0+) — new tools land to the same bar, never as loose scripts.

## Reference repos

- **`~/github-repos/repo-conventions`** — the estate-wide setup standard (labels, ruleset, docs suite).
- **`~/github-repos/huginn`** & **`~/github-repos/muninn`** — the canonical, shipped public tools; match
  their **docs suite and voice** (README / CHANGELOG / ROADMAP / CONTRIBUTING). They're Bash, not
  Python — copy the conventions and tone, not the code. Inspect the live standard with
  `huginn conventions`.
- **`packet-sniffer/`** (in this repo) — the **Python packaging model**: `src/` layout, `pyproject.toml`,
  real `tests/`. Bring the other tools up to it.
- **`~/github-repos/agent-gate`** — a further docs / CI-gate reference.
