# Dependency Management

## Overview

Python dependencies are managed with [uv](https://docs.astral.sh/uv/). Direct dependencies are declared in `pyproject.toml`; the full resolved dependency graph (including transitive deps) is recorded in `uv.lock` and committed to the repo.

Two automated systems keep dependencies up to date and secure:

| Tool | Purpose | Runs |
|------|---------|------|
| **Dependabot** | Opens PRs to bump outdated packages | Weekly (Monday mornings) |
| **pip-audit** | Blocks PRs that introduce known CVEs | On every PR touching `pyproject.toml` / `uv.lock` |

This mirrors the setup used in [commcare-hq](https://github.com/dimagi/commcare-hq), which also runs Dependabot with the native `uv` ecosystem — keeping dependency tooling consistent across Dimagi repos.

---

## Dependabot

Config: [`.github/dependabot.yml`](../.github/dependabot.yml)

Dependabot reads `pyproject.toml` / `uv.lock` (via the native `uv` ecosystem) and the workflow files under `.github/workflows/`, then opens pull requests when newer versions are available.

**Behaviour:**
- Minor and patch updates are **grouped into a single weekly PR** (`python-non-major`) to reduce noise
- Major version bumps get **individual PRs** so each breaking change can be assessed separately
- GitHub Actions are updated weekly
- Up to 5 concurrent open PRs per ecosystem

**Reviewing a Dependabot PR:**
1. Check the linked changelog for breaking changes
2. Confirm the CI `Security Audit` and `CI` jobs pass
3. For major bumps, check whether any direct call sites in our code are affected (Dependabot links to release notes)

---

## pip-audit (Security Audit CI job)

Config: [`.github/workflows/security.yml`](../.github/workflows/security.yml)

Runs on every pull request targeting `main` that modifies `pyproject.toml` or `uv.lock`. It exports the production dependency set (`uv export --no-dev`) and runs `uvx pip-audit` against it. The job fails if any package has a known vulnerability in the OSV / PyPI Advisory databases.

Dev-only dependencies (`[dependency-groups.dev]`) are excluded from the scan.

---

## Updating dependencies manually

```bash
# Bump a single package
uv add <package>==<version>

# Regenerate the lock after editing pyproject.toml directly
uv lock

# Verify the lock is consistent without changing it
uv lock --check

# Sync your local environment to the current lock
uv sync
```

After bumping, run the full test suite before committing:

```bash
uv run pytest
uv run pre-commit run -a
```

---

## Adding a new dependency

```bash
uv add <package>          # runtime dependency
uv add --dev <package>    # dev/test-only dependency
```

`uv` will update both `pyproject.toml` and `uv.lock` automatically.

---

## Periodic full audit

For a deeper review (major version bumps, EoL packages, CVE triage), run the `/audit-dependencies` skill in Claude Code.
