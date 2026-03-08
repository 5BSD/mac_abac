#!/bin/sh
#
# Test: vlabelctl command-line tool functionality
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built and in PATH or specified
#
# Usage:
#   ./02_vlabelctl.sh [path_to_vlabelctl]
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
    echo "Module not loaded. Please run 01_load_unload.sh first or load the module."
    exit 1
fi

echo "============================================"
echo "vlabelctl Functionality Tests"
echo "============================================"
echo ""

# Save original settings to restore later
ORIG_MODE=$("$VLABELCTL" mode)
ORIG_AUDIT=$("$VLABELCTL" audit)
ORIG_DEFAULT=$("$VLABELCTL" default)

# ===========================================
# Mode tests
# ===========================================
info "=== Mode Tests ==="

run_test
info "Test: Get current mode"
if "$VLABELCTL" mode >/dev/null 2>&1; then
    pass "mode get"
else
    fail "mode get"
fi

run_test
info "Test: Set mode to disabled"
if "$VLABELCTL" mode disabled >/dev/null 2>&1; then
    MODE=$("$VLABELCTL" mode)
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
if "$VLABELCTL" mode permissive >/dev/null 2>&1; then
    MODE=$("$VLABELCTL" mode)
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
# switch back to permissive. We can't use vlabelctl after setting enforcing
# because the module will block it (no rules allow vlabelctl to execute).
if sysctl security.mac.vlabel.mode=2 >/dev/null 2>&1; then
    MODE=$(sysctl -n security.mac.vlabel.mode)
    # Immediately switch back to permissive before checking
    sysctl security.mac.vlabel.mode=1 >/dev/null 2>&1
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
if "$VLABELCTL" mode invalid 2>/dev/null; then
    fail "invalid mode accepted"
else
    pass "invalid mode rejected"
fi

# ===========================================
# Audit tests
# ===========================================
info ""
info "=== Audit Tests ==="

run_test
info "Test: Get current audit level"
if "$VLABELCTL" audit >/dev/null 2>&1; then
    pass "audit get"
else
    fail "audit get"
fi

for level in none denials decisions verbose; do
    run_test
    info "Test: Set audit to $level"
    if "$VLABELCTL" audit $level >/dev/null 2>&1; then
        AUDIT=$("$VLABELCTL" audit)
        if [ "$AUDIT" = "$level" ]; then
            pass "audit set $level"
        else
            fail "audit set $level (got: $AUDIT)"
        fi
    else
        fail "audit set $level"
    fi
done

run_test
info "Test: Invalid audit level rejected"
if "$VLABELCTL" audit invalid 2>/dev/null; then
    fail "invalid audit level accepted"
else
    pass "invalid audit level rejected"
fi

# ===========================================
# Default policy tests
# ===========================================
info ""
info "=== Default Policy Tests ==="

run_test
info "Test: Get current default policy"
if "$VLABELCTL" default >/dev/null 2>&1; then
    pass "default get"
else
    fail "default get"
fi

run_test
info "Test: Set default policy to allow"
if "$VLABELCTL" default allow >/dev/null 2>&1; then
    DEFAULT=$("$VLABELCTL" default)
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
if "$VLABELCTL" default deny >/dev/null 2>&1; then
    DEFAULT=$("$VLABELCTL" default)
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
if "$VLABELCTL" default invalid 2>/dev/null; then
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
if "$VLABELCTL" stats >/dev/null 2>&1; then
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
OUTPUT=$("$VLABELCTL" status 2>&1)
if echo "$OUTPUT" | grep -q "Mode:"; then
    if echo "$OUTPUT" | grep -q "Audit:"; then
        if echo "$OUTPUT" | grep -q "Default policy:"; then
            pass "status output complete"
        else
            fail "status missing default policy"
        fi
    else
        fail "status missing audit"
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
"$VLABELCTL" rule clear >/dev/null 2>&1

run_test
info "Test: List rules (empty)"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -qi "no rules"; then
    pass "rule list empty"
else
    fail "rule list empty"
fi

run_test
info "Test: Add allow rule"
if "$VLABELCTL" rule add "allow exec * -> *" >/dev/null 2>&1; then
    pass "rule add allow"
else
    fail "rule add allow"
fi

run_test
info "Test: Add deny rule"
if "$VLABELCTL" rule add "deny exec type=user -> type=untrusted" >/dev/null 2>&1; then
    pass "rule add deny"
else
    fail "rule add deny"
fi

run_test
info "Test: Add transition rule"
if "$VLABELCTL" rule add "transition exec * -> type=setuid => type=admin" >/dev/null 2>&1; then
    pass "rule add transition"
else
    fail "rule add transition"
fi

run_test
info "Test: List rules (populated)"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
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
    if "$VLABELCTL" rule remove "$RULE_ID" >/dev/null 2>&1; then
        pass "rule remove"
    else
        fail "rule remove"
    fi
else
    fail "rule remove (could not parse rule ID)"
fi

run_test
info "Test: Clear all rules"
if "$VLABELCTL" rule clear >/dev/null 2>&1; then
    OUTPUT=$("$VLABELCTL" rule list 2>&1)
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
if "$VLABELCTL" rule add "invalid syntax here" 2>/dev/null; then
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
"$VLABELCTL" rule clear >/dev/null 2>&1
DENY_RESULT=$("$VLABELCTL" rule add "deny exec type=user -> type=untrusted" 2>&1)
ALLOW_RESULT=$("$VLABELCTL" rule add "allow exec * -> *" 2>&1)
"$VLABELCTL" default allow >/dev/null 2>&1

# Debug: Show rules
RULES=$("$VLABELCTL" rule list 2>&1)

run_test
info "Test: Test access - should be denied"
# Note: test command returns exit code 1 for DENY, so use || true to prevent set -e from killing script
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=untrusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "test access deny"
else
    fail "test access deny (deny_rule=$DENY_RESULT, allow_rule=$ALLOW_RESULT, rules=$RULES, got: $OUTPUT)"
fi

run_test
info "Test: Test access - should be allowed"
OUTPUT=$("$VLABELCTL" test exec "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "test access allow"
else
    fail "test access allow (got: $OUTPUT)"
fi

# Clear rules
"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Restore original settings
# ===========================================
info ""
info "Restoring original settings..."
"$VLABELCTL" mode "$ORIG_MODE" >/dev/null 2>&1
"$VLABELCTL" audit "$ORIG_AUDIT" >/dev/null 2>&1
"$VLABELCTL" default "$ORIG_DEFAULT" >/dev/null 2>&1

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
