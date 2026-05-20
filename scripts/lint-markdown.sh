#!/usr/bin/env bash
# Lint project markdown. Requires: npm install -g markdownlint-cli2
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v markdownlint-cli2 >/dev/null 2>&1; then
  echo "markdownlint-cli2 not found. Install globally:" >&2
  echo "  npm install -g markdownlint-cli2" >&2
  exit 1
fi

# Optional paths, e.g. ./scripts/lint-markdown.sh README.md
if [[ $# -gt 0 ]]; then
  markdownlint-cli2 "$@"
else
  markdownlint-cli2
fi
