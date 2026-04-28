# Git Worktrees for Concurrent Development

Git worktrees allow multiple branches to be checked out simultaneously in separate directories, all sharing the same repository history. This enables multiple Claude Code instances (or developers) to work on independent tasks in parallel without conflicts.

## How worktrees work

A worktree is a linked working copy of a repository. Each worktree:

- Has its own checked-out branch and working directory
- Shares the `.git` object store with the main repo (commits, history, remotes)
- Cannot share a branch with another worktree — each must have a unique branch checked out
- Is lightweight (no full clone needed)

## Single-machine workflow

This is the simplest case: one machine, multiple Claude Code instances working in parallel.

### Setup

Each Claude Code instance calls `EnterWorktree` at the start of its task. This creates an isolated working directory and branch automatically.

```
~/repos/prometheus_pihole_exporter/                  # main repo (main branch)
~/repos/prometheus_pihole_exporter/.claude/worktrees/
  ├── workitem-dhcp-leases-collector/             # worktree on workitem/dhcp-leases-collector
  └── workitem-pihole-v6-auth/                    # worktree on workitem/pihole-v6-auth
```

### Lifecycle

1. **Start a task** — Claude Code calls `EnterWorktree`, creating a worktree and branch.
2. **Do the work** — All edits, commits, and pushes happen inside the worktree directory.
3. **Push and create PR** — The branch is pushed to the remote and a **draft** PR is created.
4. **Merge** — The user reviews and squash-merges. The head branch is auto-deleted on merge (repo setting).
5. **Cleanup** — Remove the now-orphaned worktree:
   ```bash
   git worktree remove .claude/worktrees/workitem-dhcp-leases-collector
   ```
   Or list and prune stale worktrees:
   ```bash
   git worktree list
   git worktree prune
   ```

### Parallel instances

Multiple Claude Code instances can run simultaneously. Each creates its own worktree, so:

- File edits in one worktree don't affect another
- Each instance commits and pushes its own branch independently
- No merge conflicts until branches are merged into `main`

## Multi-machine workflow

When developing across multiple machines (e.g., starting on a laptop, continuing on a desktop), worktrees require some extra steps because they are **local-only** — they never get pushed to the remote.

### What travels between machines

| Travels (via `git push/fetch`) | Local-only (per machine) |
|-------------------------------|--------------------------|
| Branches                      | Worktrees                |
| Commits                       | Worktree directory layout |
| Tags                          | `.git/worktrees/` metadata |

### Switching machines

#### On the first machine

1. Work inside a worktree as normal.
2. Commit and push the branch:
   ```bash
   git push -u origin workitem/dhcp-leases-collector
   ```

#### On the second machine

The branch exists on the remote, but there's no worktree for it yet. You need to create one:

1. **Fetch the branch:**
   ```bash
   git fetch origin
   ```

2. **Create a worktree for the existing remote branch:**
   ```bash
   git worktree add .claude/worktrees/workitem-dhcp-leases-collector workitem/dhcp-leases-collector
   ```
   If the local branch doesn't exist yet, git will create it tracking the remote automatically.

3. **Work in the worktree:**
   ```bash
   cd .claude/worktrees/workitem-dhcp-leases-collector
   ```
   Or start a Claude Code instance and point it at this directory.

#### Continuing back on the first machine

If the other machine pushed new commits:

```bash
cd .claude/worktrees/workitem-dhcp-leases-collector
git pull
```

The worktree is still there from before — you just need to pull the latest changes.

### Claude Code on a second machine

When a Claude Code instance is asked to continue work on an existing branch:

1. It should check if the branch already exists on the remote (`git branch -r`).
2. If it does, create a worktree for it rather than starting a new branch.
3. Pull the latest changes before starting work.

This is equivalent to the manual steps above, but automated within the Claude Code session.

## Common commands

```bash
# List all worktrees
git worktree list

# Create a worktree for a new branch
git worktree add .claude/worktrees/my-feature -b workitem/my-feature

# Create a worktree for an existing remote branch
git fetch origin
git worktree add .claude/worktrees/my-feature workitem/my-feature

# Remove a worktree (after branch is merged + auto-deleted)
git worktree remove .claude/worktrees/my-feature

# Clean up stale worktree references
git worktree prune
```
