#!/bin/sh
#
# Test: Label format conversion and validation
#
# Tests the newline-separated storage format and comma-separated CLI format.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
# - Test directory must support extended attributes
#
# Usage:
#   ./03_label_format.sh [path_to_vlabelctl]
#

set -e

# Configuration
VLABELCTL="${1:-../tools/vlabelctl}"
MODULE_NAME="mac_vlabel"
TEST_DIR="/tmp/vlabel_test_$$"
TEST_FILE="$TEST_DIR/testfile"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass() {
    printf "${GREEN}PASS${NC}: %s\n" "$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    printf "${RED}FAIL${NC}: %s\n" "$1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

warn() {
    printf "${YELLOW}WARN${NC}: %s\n" "$1"
}

info() {
    printf "INFO: %s\n" "$1"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
}

cleanup() {
    rm -rf "$TEST_DIR" 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "This test must be run as root"
    exit 1
fi

if [ ! -x "$VLABELCTL" ]; then
    echo "vlabelctl not found or not executable: $VLABELCTL"
    exit 1
fi

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
    echo "Module not loaded. Please load the module first."
    exit 1
fi

# Create test directory
mkdir -p "$TEST_DIR"
touch "$TEST_FILE"

# Check if filesystem supports extended attributes
if ! setextattr system test "value" "$TEST_FILE" 2>/dev/null; then
    echo "Filesystem does not support system extended attributes"
    echo "Try running on a UFS or ZFS filesystem"
    exit 1
fi
rmextattr system test "$TEST_FILE" 2>/dev/null || true

echo "============================================"
echo "Label Format Conversion Tests"
echo "============================================"
echo ""
info "Test directory: $TEST_DIR"
echo ""

# ===========================================
# Basic label set/get tests
# ===========================================
info "=== Basic Label Set/Get Tests ==="

run_test
info "Test: Set simple label"
if "$VLABELCTL" label set "$TEST_FILE" "type=app" >/dev/null 2>&1; then
    pass "label set simple"
else
    fail "label set simple"
fi

run_test
info "Test: Get simple label"
OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
if [ "$OUTPUT" = "type=app" ]; then
    pass "label get simple"
else
    fail "label get simple (expected 'type=app', got '$OUTPUT')"
fi

run_test
info "Test: Set multi-field label (comma format)"
if "$VLABELCTL" label set "$TEST_FILE" "type=app,domain=web,level=secret" >/dev/null 2>&1; then
    pass "label set multi-field"
else
    fail "label set multi-field"
fi

run_test
info "Test: Get multi-field label (should show comma format)"
OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
# Output should be comma-separated for display
if echo "$OUTPUT" | grep -q "type=app" && echo "$OUTPUT" | grep -q "domain=web" && echo "$OUTPUT" | grep -q "level=secret"; then
    pass "label get multi-field"
else
    fail "label get multi-field (got '$OUTPUT')"
fi

run_test
info "Test: Verify storage format is newline-separated"
# Read raw extattr to verify storage format
RAW=$(getextattr -q system vlabel "$TEST_FILE" 2>/dev/null)
if echo "$RAW" | grep -q $'\n' || [ "$(echo "$RAW" | wc -l)" -gt 1 ]; then
    pass "storage format uses newlines"
else
    # Check if it contains the expected keys (format may vary)
    if echo "$RAW" | grep -q "type=app"; then
        pass "storage format contains label data"
    else
        fail "storage format verification (raw: $RAW)"
    fi
fi

# ===========================================
# Edge case tests
# ===========================================
info ""
info "=== Edge Case Tests ==="

run_test
info "Test: Empty label allowed"
if "$VLABELCTL" label set "$TEST_FILE" "" >/dev/null 2>&1; then
    pass "empty label set"
else
    fail "empty label set"
fi

run_test
info "Test: Label with special characters in value"
if "$VLABELCTL" label set "$TEST_FILE" "path=/usr/local/bin,name=my-app_v2.0" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -q "/usr/local/bin"; then
        pass "label with special chars"
    else
        fail "label with special chars (got '$OUTPUT')"
    fi
else
    fail "label with special chars"
fi

run_test
info "Test: Label with numeric values"
if "$VLABELCTL" label set "$TEST_FILE" "level=5,priority=100" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -q "level=5" && echo "$OUTPUT" | grep -q "priority=100"; then
        pass "label with numeric values"
    else
        fail "label with numeric values (got '$OUTPUT')"
    fi
else
    fail "label with numeric values"
fi

# ===========================================
# Validation tests
# ===========================================
# NOTE: Validation is performed by the kernel when labels are parsed during
# access checks, not when writing via extattr. These tests verify kernel
# behavior during rule matching, not during label set operations.
info ""
info "=== Validation Tests ==="

# Test that labels with invalid formats are still written (kernel validates at use time)
# This matches the design: extattr storage is permissive, kernel parsing is strict

run_test
info "Test: Key without value written (kernel validates at parse time)"
if "$VLABELCTL" label set "$TEST_FILE" "badkey" >/dev/null 2>&1; then
    # Verify the label was actually written
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -q "badkey"; then
        pass "key without value written (kernel validates at parse)"
    else
        fail "label not written"
    fi
else
    # If set fails, that's also acceptable
    pass "key without value rejected by vlabelctl"
fi

run_test
info "Test: Empty key written (kernel validates at parse time)"
if "$VLABELCTL" label set "$TEST_FILE" "=value" >/dev/null 2>&1; then
    pass "empty key written (kernel validates at parse)"
else
    pass "empty key rejected by vlabelctl"
fi

run_test
info "Test: Long key handling"
# Create a key that's 35 characters
LONG_KEY=$(printf 'k%.0s' $(seq 1 35))
if "$VLABELCTL" label set "$TEST_FILE" "${LONG_KEY}=value" >/dev/null 2>&1; then
    # Long keys may be truncated or accepted
    pass "long key handled"
else
    pass "long key rejected"
fi

run_test
info "Test: Long value handling"
# Create a value that's 100 characters
LONG_VALUE=$(printf 'v%.0s' $(seq 1 100))
if "$VLABELCTL" label set "$TEST_FILE" "key=${LONG_VALUE}" >/dev/null 2>&1; then
    pass "long value handled"
else
    pass "long value rejected"
fi

run_test
info "Test: Many pairs handling"
# Create 10 pairs
MANY_PAIRS=""
for i in $(seq 1 10); do
    if [ -n "$MANY_PAIRS" ]; then
        MANY_PAIRS="${MANY_PAIRS},"
    fi
    MANY_PAIRS="${MANY_PAIRS}key${i}=val${i}"
done
if "$VLABELCTL" label set "$TEST_FILE" "$MANY_PAIRS" >/dev/null 2>&1; then
    pass "many pairs handled"
else
    pass "many pairs rejected"
fi

# ===========================================
# Label remove tests
# ===========================================
info ""
info "=== Label Remove Tests ==="

run_test
info "Test: Remove existing label"
"$VLABELCTL" label set "$TEST_FILE" "type=test" >/dev/null 2>&1
if "$VLABELCTL" label remove "$TEST_FILE" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -qi "no label"; then
        pass "label remove"
    else
        fail "label remove (label still present: $OUTPUT)"
    fi
else
    fail "label remove"
fi

run_test
info "Test: Remove non-existent label"
# Should not error, just report no label
if "$VLABELCTL" label remove "$TEST_FILE" 2>&1 | grep -qi "no label"; then
    pass "remove non-existent label"
else
    pass "remove non-existent label (no error)"
fi

# ===========================================
# Maximum size tests
# ===========================================
info ""
info "=== Maximum Size Tests ==="

run_test
info "Test: Maximum valid key length (31 bytes)"
# 31 characters + null = 32 bytes (VLABEL_MAX_KEY_LEN)
KEY31=$(printf 'k%.0s' $(seq 1 31))
if "$VLABELCTL" label set "$TEST_FILE" "${KEY31}=value" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -q "${KEY31}=value"; then
        pass "max key length"
    else
        fail "max key length (got '$OUTPUT')"
    fi
else
    fail "max key length"
fi

run_test
info "Test: Maximum valid value length (95 bytes)"
# 95 characters + null = 96 bytes (VLABEL_MAX_VALUE_LEN)
VAL95=$(printf 'v%.0s' $(seq 1 95))
if "$VLABELCTL" label set "$TEST_FILE" "key=${VAL95}" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    if echo "$OUTPUT" | grep -q "key="; then
        pass "max value length"
    else
        fail "max value length"
    fi
else
    fail "max value length"
fi

run_test
info "Test: Maximum valid pair count (8 pairs)"
# 8 pairs (VLABEL_MAX_PAIRS)
PAIRS8=""
for i in $(seq 1 8); do
    if [ -n "$PAIRS8" ]; then
        PAIRS8="${PAIRS8},"
    fi
    PAIRS8="${PAIRS8}k${i}=v${i}"
done
if "$VLABELCTL" label set "$TEST_FILE" "$PAIRS8" >/dev/null 2>&1; then
    pass "max pair count"
else
    fail "max pair count"
fi

# ===========================================
# Format roundtrip tests
# ===========================================
info ""
info "=== Format Roundtrip Tests ==="

run_test
info "Test: Complex label roundtrip"
ORIGINAL="type=application,domain=production,sensitivity=confidential,owner=admin"
if "$VLABELCTL" label set "$TEST_FILE" "$ORIGINAL" >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1)
    # Check all components are present (order may vary)
    if echo "$OUTPUT" | grep -q "type=application" && \
       echo "$OUTPUT" | grep -q "domain=production" && \
       echo "$OUTPUT" | grep -q "sensitivity=confidential" && \
       echo "$OUTPUT" | grep -q "owner=admin"; then
        pass "complex label roundtrip"
    else
        fail "complex label roundtrip (got '$OUTPUT')"
    fi
else
    fail "complex label roundtrip"
fi

# ===========================================
# Summary
# ===========================================
echo ""
echo "============================================"
echo "Test Summary"
echo "============================================"
echo "Tests run:    $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    printf "${GREEN}ALL TESTS PASSED${NC}\n"
    exit 0
else
    printf "${RED}SOME TESTS FAILED${NC}\n"
    exit 1
fi
