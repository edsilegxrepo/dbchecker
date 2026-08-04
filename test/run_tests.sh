#!/bin/bash
# DBChecker Test Runner
# Runs unit tests and optionally integration tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=== Building all packages ==="
go build ./...

echo ""
echo "=== Running unit tests ==="
go test ./... -v -count=1

if [[ "$1" == "--integration" || "$1" == "-i" ]]; then
  echo ""
  echo "=== Running integration tests (requires Docker) ==="
  go clean -testcache
  go test -tags=integration ./test/... -v -timeout 15m
fi

echo ""
echo "=== All tests completed successfully ==="
