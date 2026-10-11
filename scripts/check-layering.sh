#!/usr/bin/env bash
# Enforces the architectural boundaries: the domain must not depend on HTTP, databases or network I/O.
# Usage: scripts/check-layering.sh
set -euo pipefail

FORBIDDEN='^(axum|hyper|tower|tower-http|sqlx|reqwest|rusqlite|diesel|tokio-postgres|mio|socket2)$'

deps_of() {
  cargo tree -p "$1" --edges normal --prefix none --format '{p}' | awk '{print $1}' | sort -u
}

check() {
  local crate="$1"
  local deps
  deps=$(deps_of "$crate")
  if echo "$deps" | grep -E "$FORBIDDEN" >/dev/null; then
    echo "ERROR: $crate depends on forbidden crates:" >&2
    echo "$deps" | grep -E "$FORBIDDEN" >&2
    exit 1
  fi
  echo "ok: $crate"
}

check passguardian-server-domain
check passguardian-core
check passguardian-proto

# server-data must not depend on the HTTP layer
for crate in passguardian-server-data; do
  deps=$(deps_of "$crate")
  if echo "$deps" | grep -E '^(axum|hyper|tower-http)$' >/dev/null; then
    echo "ERROR: $crate depends on the HTTP layer" >&2
    exit 1
  fi
  echo "ok: $crate"
done
