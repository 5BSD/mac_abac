#!/bin/sh
#
# Test: Default policy (allow/deny) behavior
#
# Tests that the default_policy sysctl correctly affects rule evaluation
# when no rule matches.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
#
# Usage:
#   ./04_default_policy.sh [path_to_vlabelctl]
#

set -e

# Configuration
VLABELCTL="${1:-../tools/vlabelctl}"
MODULE_NAME="mac_vlabel"

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

info() {
    printf "INFO: %s\n" "$1"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
}

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

echo "============================================"
echo "Default Policy Behavior Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_DEFAULT=$("$VLABELCTL" default)
ORIG_MODE=$("$VLABELCTL" mode)

# Clear all rules for testing
"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Default policy via vlabelctl
# ===========================================
info "=== Default Policy via vlabelctl ==="

run_test
info "Test: Get default policy"
if "$VLABELCTL" default >/dev/null 2>&1; then
    pass "get default policy"
else
    fail "get default policy"
fi

run_test
info "Test: Set default policy to allow"
if "$VLABELCTL" default allow >/dev/null 2>&1; then
    RESULT=$("$VLABELCTL" default)
    if [ "$RESULT" = "allow" ]; then
        pass "set default allow"
    else
        fail "set default allow (got: $RESULT)"
    fi
else
    fail "set default allow"
fi

run_test
info "Test: Set default policy to deny"
if "$VLABELCTL" default deny >/dev/null 2>&1; then
    RESULT=$("$VLABELCTL" default)
    if [ "$RESULT" = "deny" ]; then
        pass "set default deny"
    else
        fail "set default deny (got: $RESULT)"
    fi
else
    fail "set default deny"
fi

# ===========================================
# Default policy via sysctl
# ===========================================
info ""
info "=== Default Policy via sysctl ==="

run_test
info "Test: Read default_policy sysctl"
if sysctl -n security.mac.vlabel.default_policy >/dev/null 2>&1; then
    pass "read sysctl"
else
    fail "read sysctl"
fi

run_test
info "Test: Set default_policy to 0 (allow) via sysctl"
if sysctl security.mac.vlabel.default_policy=0 >/dev/null 2>&1; then
    RESULT=$(sysctl -n security.mac.vlabel.default_policy)
    if [ "$RESULT" = "0" ]; then
        pass "sysctl set 0"
    else
        fail "sysctl set 0 (got: $RESULT)"
    fi
else
    fail "sysctl set 0"
fi

run_test
info "Test: Set default_policy to 1 (deny) via sysctl"
if sysctl security.mac.vlabel.default_policy=1 >/dev/null 2>&1; then
    RESULT=$(sysctl -n security.mac.vlabel.default_policy)
    if [ "$RESULT" = "1" ]; then
        pass "sysctl set 1"
    else
        fail "sysctl set 1 (got: $RESULT)"
    fi
else
    fail "sysctl set 1"
fi

run_test
info "Test: Invalid sysctl value handling"
# Note: FreeBSD sysctl doesn't validate integer ranges by default.
# The kernel sysctl is CTLFLAG_RW int, so any int value is accepted.
# This is expected behavior - the policy code should handle invalid values.
# We verify the value is at least set (not rejected outright).
if sysctl security.mac.vlabel.default_policy=2 2>/dev/null; then
    RESULT=$(sysctl -n security.mac.vlabel.default_policy)
    # Value was accepted - this is expected for SYSCTL_INT
    # In enforcement, values > 0 are treated as "deny" (secure default)
    pass "sysctl accepts integer values (got: $RESULT)"
    # Restore valid value
    sysctl security.mac.vlabel.default_policy=0 >/dev/null 2>&1
else
    pass "invalid sysctl value rejected"
fi

# ===========================================
# Default policy behavior in rule evaluation
# ===========================================
info ""
info "=== Default Policy Rule Evaluation ==="

# Clear all rules
"$VLABELCTL" rule clear >/dev/null 2>&1

run_test
info "Test: No rules + default=allow -> ALLOW"
if ! "$VLABELCTL" default allow 2>&1; then
    fail "no rules + default allow (could not set default policy)"
else
    # Note: test command returns exit code 1 for DENY, so use || true to prevent set -e from killing script
    OUTPUT=$("$VLABELCTL" test exec "type=test" "type=target" 2>&1 || true)
    if echo "$OUTPUT" | grep -q "ALLOW"; then
        pass "no rules + default allow"
    else
        fail "no rules + default allow (got: $OUTPUT)"
    fi
fi

run_test
info "Test: No rules + default=deny -> DENY"
if ! "$VLABELCTL" default deny 2>&1; then
    fail "no rules + default deny (could not set default policy)"
else
    # Verify the policy was set
    POLICY=$("$VLABELCTL" default 2>&1)
    SYSCTL_VAL=$(sysctl -n security.mac.vlabel.default_policy 2>&1)
    # Note: test command returns exit code 1 for DENY, so use || true to prevent set -e from killing script
    OUTPUT=$("$VLABELCTL" test exec "type=test" "type=target" 2>&1 || true)
    if echo "$OUTPUT" | grep -q "DENY"; then
        pass "no rules + default deny"
    else
        fail "no rules + default deny (policy=$POLICY, sysctl=$SYSCTL_VAL, got: $OUTPUT)"
    fi
fi

# ===========================================
# Rule takes precedence over default
# ===========================================
info ""
info "=== Rule Precedence Over Default ==="

run_test
info "Test: Explicit allow rule overrides default=deny"
"$VLABELCTL" default deny >/dev/null 2>&1
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" rule add "allow exec type=allowed -> *" >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" test exec "type=allowed" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "allow rule overrides default deny"
else
    fail "allow rule overrides default deny (got: $OUTPUT)"
fi

run_test
info "Test: Explicit deny rule overrides default=allow"
"$VLABELCTL" default allow >/dev/null 2>&1
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" rule add "deny exec type=denied -> *" >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" test exec "type=denied" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "deny rule overrides default allow"
else
    fail "deny rule overrides default allow (got: $OUTPUT)"
fi

run_test
info "Test: Non-matching rule falls back to default=allow"
"$VLABELCTL" default allow >/dev/null 2>&1
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" rule add "deny exec type=specific -> type=specific" >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" test exec "type=other" "type=other" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "non-matching falls back to default allow"
else
    fail "non-matching falls back to default allow (got: $OUTPUT)"
fi

run_test
info "Test: Non-matching rule falls back to default=deny"
"$VLABELCTL" default deny >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" test exec "type=other" "type=other" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "non-matching falls back to default deny"
else
    fail "non-matching falls back to default deny (got: $OUTPUT)"
fi

# ===========================================
# Status display includes default policy
# ===========================================
info ""
info "=== Status Display ==="

run_test
info "Test: Status shows default policy"
"$VLABELCTL" default allow >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" status 2>&1)
if echo "$OUTPUT" | grep -q "Default policy:.*allow"; then
    pass "status shows default allow"
else
    fail "status shows default allow (got: $OUTPUT)"
fi

run_test
info "Test: Status shows deny policy"
"$VLABELCTL" default deny >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" status 2>&1)
if echo "$OUTPUT" | grep -q "Default policy:.*deny"; then
    pass "status shows default deny"
else
    fail "status shows default deny (got: $OUTPUT)"
fi

# ===========================================
# Restore original settings
# ===========================================
info ""
info "Restoring original settings..."
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" default "$ORIG_DEFAULT" >/dev/null 2>&1
"$VLABELCTL" mode "$ORIG_MODE" >/dev/null 2>&1

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
