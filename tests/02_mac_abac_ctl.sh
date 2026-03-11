#!/bin/sh
#
# Test: mac_abac_ctl command-line tool functionality
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must be built and in PATH or specified
#
# Usage:
#   ./02_mac_abac_ctl.sh [path_to_mac_abac_ctl]
#

set -e

# Configuration
MAC_ABAC_CTL="${1:-../tools/mac_abac_ctl}"
MODULE_NAME="mac_abac"

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

if [ ! -x "$MAC_ABAC_CTL" ]; then
    echo "mac_abac_ctl not found or not executable: $MAC_ABAC_CTL"
    exit 1
fi

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
    echo "Module not loaded. Please run 01_load_unload.sh first or load the module."
    exit 1
fi

echo "============================================"
echo "mac_abac_ctl Functionality Tests"
echo "============================================"
echo ""

# Save original settings to restore later
ORIG_MODE=$("$MAC_ABAC_CTL" mode)
ORIG_DEFAULT=$("$MAC_ABAC_CTL" default)

# ===========================================
# Mode tests
# ===========================================
info "=== Mode Tests ==="

run_test
info "Test: Get current mode"
if "$MAC_ABAC_CTL" mode >/dev/null 2>&1; then
    pass "mode get"
else
    fail "mode get"
fi

run_test
info "Test: Set mode to disabled"
if "$MAC_ABAC_CTL" mode disabled >/dev/null 2>&1; then
    MODE=$("$MAC_ABAC_CTL" mode)
    if [ "$MODE" = "disabled" ]; then
        pass "mode set disabled"
    else
        fail "mode set disabled (got: $MODE)"
    fi
else
    fail "mode set disabled"
fi

run_test
info "Test: Set mode to permissive"
if "$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1; then
    MODE=$("$MAC_ABAC_CTL" mode)
    if [ "$MODE" = "permissive" ]; then
        pass "mode set permissive"
    else
        fail "mode set permissive (got: $MODE)"
    fi
else
    fail "mode set permissive"
fi

run_test
info "Test: Set mode to enforcing"
# Note: We set enforcing mode via sysctl, then check, then immediately
# switch back to permissive. We can't use mac_abac_ctl after setting enforcing
# because the module will block it (no rules allow mac_abac_ctl to execute).
if sysctl security.mac.abac.mode=2 >/dev/null 2>&1; then
    MODE=$(sysctl -n security.mac.abac.mode)
    # Immediately switch back to permissive before checking
    sysctl security.mac.abac.mode=1 >/dev/null 2>&1
    if [ "$MODE" = "2" ]; then
        pass "mode set enforcing"
    else
        fail "mode set enforcing (got: $MODE)"
    fi
else
    fail "mode set enforcing"
fi

run_test
info "Test: Invalid mode rejected"
if "$MAC_ABAC_CTL" mode invalid 2>/dev/null; then
    fail "invalid mode accepted"
else
    pass "invalid mode rejected"
fi

# ===========================================
# Default policy tests
# ===========================================
info ""
info "=== Default Policy Tests ==="

run_test
info "Test: Get current default policy"
if "$MAC_ABAC_CTL" default >/dev/null 2>&1; then
    pass "default get"
else
    fail "default get"
fi

run_test
info "Test: Set default policy to allow"
if "$MAC_ABAC_CTL" default allow >/dev/null 2>&1; then
    DEFAULT=$("$MAC_ABAC_CTL" default)
    if [ "$DEFAULT" = "allow" ]; then
        pass "default set allow"
    else
        fail "default set allow (got: $DEFAULT)"
    fi
else
    fail "default set allow"
fi

run_test
info "Test: Set default policy to deny"
if "$MAC_ABAC_CTL" default deny >/dev/null 2>&1; then
    DEFAULT=$("$MAC_ABAC_CTL" default)
    if [ "$DEFAULT" = "deny" ]; then
        pass "default set deny"
    else
        fail "default set deny (got: $DEFAULT)"
    fi
else
    fail "default set deny"
fi

run_test
info "Test: Invalid default policy rejected"
if "$MAC_ABAC_CTL" default invalid 2>/dev/null; then
    fail "invalid default policy accepted"
else
    pass "invalid default policy rejected"
fi

# ===========================================
# Stats tests
# ===========================================
info ""
info "=== Stats Tests ==="

run_test
info "Test: Get statistics"
if "$MAC_ABAC_CTL" stats >/dev/null 2>&1; then
    pass "stats"
else
    fail "stats"
fi

# ===========================================
# Status tests
# ===========================================
info ""
info "=== Status Tests ==="

run_test
info "Test: Get combined status"
OUTPUT=$("$MAC_ABAC_CTL" status 2>&1)
if echo "$OUTPUT" | grep -q "Mode:"; then
    if echo "$OUTPUT" | grep -q "Default policy:"; then
        pass "status output complete"
    else
        fail "status missing default policy"
    fi
else
    fail "status missing mode"
fi

# ===========================================
# Rule tests
# ===========================================
info ""
info "=== Rule Tests ==="

# Clear any existing rules
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

run_test
info "Test: List rules (empty)"
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
if echo "$OUTPUT" | grep -qi "no rules"; then
    pass "rule list empty"
else
    fail "rule list empty"
fi

run_test
info "Test: Add allow rule"
if "$MAC_ABAC_CTL" rule add "allow exec * -> *" >/dev/null 2>&1; then
    pass "rule add allow"
else
    fail "rule add allow"
fi

run_test
info "Test: Add deny rule"
if "$MAC_ABAC_CTL" rule add "deny exec type=user -> type=untrusted" >/dev/null 2>&1; then
    pass "rule add deny"
else
    fail "rule add deny"
fi

run_test
info "Test: Add transition rule"
if "$MAC_ABAC_CTL" rule add "transition exec * -> type=setuid => type=admin" >/dev/null 2>&1; then
    pass "rule add transition"
else
    fail "rule add transition"
fi

run_test
info "Test: List rules (populated)"
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "Loaded rules: 3"; then
    pass "rule list populated"
else
    fail "rule list populated (got: $OUTPUT)"
fi

run_test
info "Test: Remove rule"
# Get the first rule ID from list output
RULE_ID=$(echo "$OUTPUT" | grep '^\s*\[' | head -1 | sed 's/.*\[\([0-9]*\)\].*/\1/')
if [ -n "$RULE_ID" ]; then
    if "$MAC_ABAC_CTL" rule remove "$RULE_ID" >/dev/null 2>&1; then
        pass "rule remove"
    else
        fail "rule remove"
    fi
else
    fail "rule remove (could not parse rule ID)"
fi

run_test
info "Test: Clear all rules"
if "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1; then
    OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
    if echo "$OUTPUT" | grep -qi "no rules"; then
        pass "rule clear"
    else
        fail "rule clear (rules still present)"
    fi
else
    fail "rule clear"
fi

run_test
info "Test: Invalid rule syntax rejected"
if "$MAC_ABAC_CTL" rule add "invalid syntax here" 2>/dev/null; then
    fail "invalid rule syntax accepted"
else
    pass "invalid rule syntax rejected"
fi

# ===========================================
# Test access tests
# ===========================================
info ""
info "=== Test Access Tests ==="

# Set up rules for testing
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
DENY_RESULT=$("$MAC_ABAC_CTL" rule add "deny exec type=user -> type=untrusted" 2>&1)
ALLOW_RESULT=$("$MAC_ABAC_CTL" rule add "allow exec * -> *" 2>&1)
"$MAC_ABAC_CTL" default allow >/dev/null 2>&1

# Debug: Show rules
RULES=$("$MAC_ABAC_CTL" rule list 2>&1)

run_test
info "Test: Test access - should be denied"
# Note: test command returns exit code 1 for DENY, so use || true to prevent set -e from killing script
OUTPUT=$("$MAC_ABAC_CTL" test exec "type=user" "type=untrusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "test access deny"
else
    fail "test access deny (deny_rule=$DENY_RESULT, allow_rule=$ALLOW_RESULT, rules=$RULES, got: $OUTPUT)"
fi

run_test
info "Test: Test access - should be allowed"
OUTPUT=$("$MAC_ABAC_CTL" test exec "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "test access allow"
else
    fail "test access allow (got: $OUTPUT)"
fi

# Clear rules
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

# ===========================================
# Restore original settings
# ===========================================
info ""
info "Restoring original settings..."
"$MAC_ABAC_CTL" mode "$ORIG_MODE" >/dev/null 2>&1
"$MAC_ABAC_CTL" default "$ORIG_DEFAULT" >/dev/null 2>&1

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
