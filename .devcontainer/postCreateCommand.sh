#!/bin/bash
# .devcontainer/postCreateCommand.sh
#
# Runs once when the dev container is first created (or rebuilt).

set -euo pipefail

: "${WORKSPACE_DIR:=/workspaces/$(basename "$PWD")}"

# 1) Workspace ownership — features sometimes leave files owned by root.
sudo chown -R vscode:vscode "$WORKSPACE_DIR" 2>/dev/null || true
sudo chown -R vscode:vscode "$HOME/.claude" 2>/dev/null || true

# 2) Pre-fetch Go modules so the first build is instant.
if [ -f "$WORKSPACE_DIR/go.mod" ]; then
  ( cd "$WORKSPACE_DIR" && go mod download )
fi

# 3) Install golangci-lint at the version CI runs against. Pinning so a
#    runtime-fresh devcontainer matches the linter behaviour reviewers see
#    on the PR.
GOLANGCI_VERSION="${GOLANGCI_VERSION:-v2.3.0}"
GOPATH_BIN="$(go env GOPATH 2>/dev/null)/bin"
mkdir -p "$GOPATH_BIN"
if ! "$GOPATH_BIN/golangci-lint" version --short 2>/dev/null | grep -q "${GOLANGCI_VERSION#v}"; then
  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b "$GOPATH_BIN" "$GOLANGCI_VERSION"
fi

# 4) gofumpt is referenced by editor settings; install it lazily.
go install mvdan.cc/gofumpt@latest

echo
echo "[postCreate] dev container ready."
echo "  go         : $(go version 2>/dev/null || echo 'not found')"
echo "  lint       : $("$GOPATH_BIN/golangci-lint" version --short 2>/dev/null || echo 'not found')"
echo "  gh         : $(gh --version 2>/dev/null | head -1 || echo 'not found')"
echo
