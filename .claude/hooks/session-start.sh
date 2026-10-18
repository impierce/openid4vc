#!/bin/bash
# SessionStart hook for Claude Code cloud sessions.
#
# Cloud sessions start from a fresh container that has Rust but none of the cargo tools
# CONTRIBUTING.md asks for, so agents could not run the same checks as CI. This script installs
# them and warms the dependency cache. It only runs in cloud sessions ($CLAUDE_CODE_REMOTE); local
# sessions are left alone. The container state is cached after the hook completes, so later
# sessions start quickly. Safe to run repeatedly.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# Install a cargo subcommand unless its binary is already on PATH. cargo-binstall is used when
# available (prebuilt binaries); otherwise the tool is compiled from crates.io.
install_tool() {
  local crate=$1 bin=$2
  if command -v "$bin" >/dev/null 2>&1; then
    echo "session-start: $bin already installed"
    return
  fi
  echo "session-start: installing $crate"
  if command -v cargo-binstall >/dev/null 2>&1; then
    cargo binstall -y "$crate"
  else
    cargo install --locked "$crate"
  fi
}

rustup component add rustfmt clippy llvm-tools-preview

install_tool cargo-deny cargo-deny
install_tool cargo-llvm-cov cargo-llvm-cov
install_tool cargo-hack cargo-hack

# Fetch the dependency graph (including the git dependencies) so the first build is offline-fast.
cargo fetch

echo "session-start: done"
