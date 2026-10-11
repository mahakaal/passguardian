#!/usr/bin/env bash
# Runs locally the same checks as CI. Usage: scripts/verify.sh
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$1"; }

step "Formatting";  cargo fmt --all --check
step "Clippy (-D warnings)"; cargo clippy --workspace --all-targets --locked -- -D warnings
step "Tests";       cargo test --workspace --locked
step "Layering";    bash scripts/check-layering.sh
if command -v cargo-deny >/dev/null 2>&1; then
  step "cargo-deny (licenses, bans, sources)"; cargo deny check licenses bans sources
else
  echo "WARNING: cargo-deny is not installed, check skipped (cargo install cargo-deny --locked)" >&2
fi
printf '\nEverything verified.\n'
