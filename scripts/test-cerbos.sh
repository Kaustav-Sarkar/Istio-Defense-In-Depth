#!/usr/bin/env bash
set -euo pipefail

echo "Running Cerbos policy tests..."
docker run --rm --workdir / -v "$(pwd)/cerbos:/work:ro" ghcr.io/cerbos/cerbos:0.35.0 compile /work/policies --tests /work/tests

echo "Cerbos tests passed."
