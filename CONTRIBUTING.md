# Contributing & Repo Conventions

This repo follows the same guardrails as the rest of the `brett-buskirk` estate. Read this before
pushing code. The full cleanup plan is in [CLAUDE.md](CLAUDE.md).

## Branch & PR workflow (required)

- **No direct commits to `main`.** `main` is protected by a branch ruleset requiring pull requests.
- Work on a feature branch, then open a PR with the `gh` CLI:
  ```bash
  git checkout -b <type>/<short-name>     # e.g. refactor/unify-module-names
  git push -u origin <branch>
  gh pr create --fill
  ```
- Assign `brett-buskirk` to issues and PRs. Prefer a stack of focused PRs over one giant diff.

## AgentGate runs on every PR

Config in `.agentgate.yml`: `secrets` and `dangerous_patterns` are hard **errors**; `scope`,
`diff_size`, `tests_required`, and `dependencies` are **warnings**. Only the two errors block a
merge. Restructuring PRs (renames, moves) will trip non-blocking `scope`/`diff_size` warnings —
that's expected.

## Python conventions (target)

Once the toolkit is restructured (see CLAUDE.md), the intended standard is:
- One root `pyproject.toml`; a `src/` package layout; valid module names (`ssh_cmd.py`, not `ssh-cmd.py`).
- `ruff` for lint + format, `mypy` for types, `pytest` for tests — run all three locally before pushing.
- A CI gate (lint → typecheck → test) will enforce this once added.

## Secrets — hard rules

Never commit SSH keys, `.env`, `*.pem`/`*.key`, or captured traffic. `.gitignore` covers these.
The SSH server / reverse-shell tools are **educational**; keep them documented as such.

## Repo facts

- **Public** repository, default branch `main`. Owner: Brett Buskirk (Brett Buskirk LLC).
