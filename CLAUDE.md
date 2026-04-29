# Project: prometheus_pihole_exporter

Prometheus exporter for Pi-hole v6. Exposes DNS, blocking, and DHCP metrics from one or more Pi-hole instances. Single static Go binary; published as a multi-arch container on `ghcr.io/reloaded/prometheus_pihole_exporter`.

## Commit style

- Do not add Co-Authored-By lines to commit messages.
- Keep commit messages concise: imperative mood, 1-2 sentence summary.

## Key documentation

- `README.md` — user-facing run + config docs
- `docs/worktrees.md` — git worktrees for concurrent and multi-machine development
- `docs/architecture.md` — collector / config / scrape pattern (added once non-trivial)
- `docs/pihole-v6-api.md` — notes on the Pi-hole v6 REST surface we depend on (auth model, endpoints, gotchas)

## Language + layout

- Go ≥ 1.23, single module rooted at the repo
- Entrypoint: `cmd/prometheus_pihole_exporter/main.go`
- Library code under `internal/` (not importable from outside the module)
  - `internal/config` — config loader (YAML + env)
  - `internal/pihole` — Pi-hole v6 API client (auth + endpoints)
  - `internal/exporter` — Prometheus collectors per group (`dns`, `dhcp_leases`, `dhcp_log`)
- Use `prometheus/client_golang` for metric registration; one `prometheus.Collector` per logical group
- Multi-target pattern: one HTTP handler at `/probe` accepts `?target=<instance-id>` and runs the per-instance collectors. `/metrics` only carries exporter-self metrics. Same shape blackbox uses

## Test conventions

- `_test.go` next to the file under test
- Table-driven tests preferred
- Pi-hole API client: tests use `httptest.Server` (no live cluster)
- DHCP log parser: tests use captured fixture log lines under `testdata/`
- `make test` and `make lint` must pass before opening a PR; CI enforces

## Lint / format

- `gofmt -s` (strict)
- `golangci-lint` with the linters in `.golangci.yml` — additions require a PR-level discussion
- No `nolint` comments without a one-line explanation
- **Use `make lint` — never bare `golangci-lint`.** The Makefile reads the pinned version from `.golangci-lint-version` and runs the project-local binary at `./bin/golangci-lint-<version>`. The same file feeds the CI workflow and the devcontainer's `postCreateCommand.sh` so the three never drift. Bumping the version is a single-file edit.

## Git workflow

- **NEVER commit directly to `main` or push to `main`. All work MUST be done on a feature branch. Absolute rule.**
- Create a `workitem/` feature branch (e.g. `workitem/dhcp-leases-collector`) before making any changes
- Each logical task → **one commit** containing all the changes from that task. No file-per-commit splatter
- When a task is complete:
  1. Stage all changed files from the task
  2. Commit to the feature branch with a concise message
  3. Push the commit to the remote branch
  4. Create a **draft** PR via `gh pr create --draft` if one doesn't exist
- Do not wait to be asked to commit/push — finish, commit, push, then move on
- **Always create PRs as drafts.** The user marks ready for review. Never flip draft state on subsequent pushes
- The repo is configured for **squash merges only** with **auto-delete of head branches on merge**. PR titles become the final commit message — write them well. Individual commits on the branch can be terse since they get squashed away
- Do not merge PRs — leave them for the user

## Release / image publishing

- Tags follow semver (`v0.1.0`, `v0.2.0-rc1`, …). Push a signed tag → release workflow runs
- Release workflow builds **multi-arch** images (linux/amd64 + linux/arm64) and publishes to `ghcr.io/reloaded/prometheus_pihole_exporter` with these tag aliases:
  - `:vX.Y.Z` (the semver tag)
  - `:vX.Y` and `:vX` (rolling minor/major)
  - `:latest` (only on non-prerelease tags)
  - `:sha-<short>` (the commit short SHA — useful for pinning during incident response)
- Pre-release tags (`-rc`, `-alpha`, `-beta`) skip `:latest` and the rolling minor/major aliases

## Concurrent work with worktrees

Multiple Claude Code instances can work in parallel on separate tasks. Each instance **must** use a git worktree to avoid conflicts. See `docs/worktrees.md` for full details.

**At the start of every task**, use the `EnterWorktree` tool to create an isolated worktree for your branch.

- Two worktrees cannot have the same branch checked out simultaneously
- When the PR is merged (and the head branch auto-deleted), clean the worktree with `git worktree remove`

### Multi-machine workflow

Worktrees are local-only — they don't get pushed. To continue work on an existing remote branch from another machine:

1. `git fetch origin`
2. `git worktree add .claude/worktrees/<name> workitem/<branch>`
3. Pull before starting

If asked to continue work on an existing remote branch, check `git branch -r` first and create a worktree for it rather than starting a fresh branch.
