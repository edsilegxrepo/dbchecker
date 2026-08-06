#!/bin/bash
# DBChecker Test Runner
#
# Usage:
#   ./test/run_tests.sh           # Run unit tests only
#   ./test/run_tests.sh int       # Run integration tests (Docker required)
#   ./test/run_tests.sh stress    # Run stress tests
#   ./test/run_tests.sh all       # Run all tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

run_build() {
    echo "=== Building all packages ==="
    go build ./...
}

run_unit() {
    echo "=== Running unit tests ==="
    go test ./... -v -count=1
}

run_integration() {
    echo "=== Running integration tests (Docker required) ==="
    go clean -testcache
    go test -tags=integration ./test/... -v -timeout 15m
}

run_stress() {
    echo "=== Running stress tests ==="
    go test -tags=stress ./test/... -v -timeout 5m
}

case "${1:-unit}" in
    unit|"")
        run_build
        echo ""
        run_unit
        ;;
    int|integration|-i|--integration)
        run_build
        echo ""
        run_integration
        ;;
    stress)
        run_build
        echo ""
        run_stress
        ;;
    all)
        run_build
        echo ""
        run_unit
        echo ""
        run_integration
        echo ""
        run_stress
        ;;
    *)
        echo "Usage: $0 [unit|int|stress|all]"
        exit 1
        ;;
esac

echo ""
echo "=== All tests completed successfully ==="
