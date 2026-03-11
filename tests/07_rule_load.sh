#!/bin/sh
#
# Test: Rule loading from file (mac_abac_ctl rule load)
#
# Tests the rule load feature which loads multiple rules from a file.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must be built
#
# Usage:
#   ./07_rule_load.sh [path_to_mac_abac_ctl]
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration - find mac_abac_ctl relative to script location
if [ -n "$1" ]; then
	MAC_ABAC_CTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="$SCRIPT_DIR/../tools/mac_abac_ctl"
else
	MAC_ABAC_CTL="./tools/mac_abac_ctl"
fi
MODULE_NAME="mac_abac"
FIXTURES="$SCRIPT_DIR/fixtures/policies"

# Check prerequisites
require_root
require_mac_abac_ctl

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

if [ ! -d "$FIXTURES" ]; then
	echo "Fixtures directory not found: $FIXTURES"
	exit 1
fi

# Cleanup function
cleanup() {
	"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
}

echo "============================================"
echo "Rule Load Tests"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
info "Using fixtures: $FIXTURES"
echo ""

# Clear any existing rules
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

# ===========================================
# Basic load tests
# ===========================================
info "=== Basic Load Tests ==="

run_test
info "Test: Load minimal.rules"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/minimal.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 1 rules"; then
	pass "load minimal.rules"
else
	fail "load minimal.rules (got: $OUTPUT)"
fi

run_test
info "Test: Verify rule was loaded"
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "allow"; then
	pass "rule appears in list"
else
	fail "rule appears in list (got: $OUTPUT)"
fi

run_test
info "Test: Load web_sandbox.rules"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/web_sandbox.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	# Count should be more than 1
	COUNT=$(echo "$OUTPUT" | grep -o 'loaded [0-9]*' | grep -o '[0-9]*')
	if [ "$COUNT" -gt 1 ]; then
		pass "load web_sandbox.rules ($COUNT rules)"
	else
		fail "load web_sandbox.rules (expected multiple rules)"
	fi
else
	fail "load web_sandbox.rules (got: $OUTPUT)"
fi

run_test
info "Test: Load multi_tenant.rules"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/multi_tenant.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	pass "load multi_tenant.rules"
else
	fail "load multi_tenant.rules (got: $OUTPUT)"
fi

run_test
info "Test: Load valid_complete.rules"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/valid_complete.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	pass "load valid_complete.rules"
else
	fail "load valid_complete.rules (got: $OUTPUT)"
fi

# ===========================================
# Error handling tests
# ===========================================
echo ""
info "=== Error Handling Tests ==="

run_test
info "Test: Load invalid_syntax.rules reports errors"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/invalid_syntax.rules" 2>&1 || true)
if echo "$OUTPUT" | grep -q "errors"; then
	pass "invalid file reports errors"
else
	fail "invalid file reports errors (got: $OUTPUT)"
fi

run_test
info "Test: Atomic load aborts on parse error (no partial load)"
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
if echo "$OUTPUT" | grep -qi "no rules"; then
	pass "atomic load aborts on error (no rules loaded)"
else
	fail "atomic load should abort on error (got: $OUTPUT)"
fi

run_test
info "Test: Non-existent file fails"
if "$MAC_ABAC_CTL" rule load "/nonexistent/file.rules" >/dev/null 2>&1; then
	fail "non-existent file fails"
else
	pass "non-existent file fails"
fi

# ===========================================
# Append behavior tests
# ===========================================
echo ""
info "=== Append Behavior Tests ==="

run_test
info "Test: Load replaces existing rules (atomic)"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
"$MAC_ABAC_CTL" rule add "deny exec * -> type=first" >/dev/null 2>&1
"$MAC_ABAC_CTL" rule add "deny exec * -> type=second" >/dev/null 2>&1
BEFORE=$("$MAC_ABAC_CTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
"$MAC_ABAC_CTL" rule load "$FIXTURES/minimal.rules" >/dev/null 2>&1
AFTER=$("$MAC_ABAC_CTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
# Load should replace, so AFTER should be 1 (minimal.rules has 1 rule)
if [ "$AFTER" -eq 1 ]; then
	pass "load replaces existing rules (atomic)"
else
	fail "load replaces existing rules (before: $BEFORE, after: $AFTER, expected: 1)"
fi

run_test
info "Test: Append adds to existing rules"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
"$MAC_ABAC_CTL" rule add "deny exec * -> type=first" >/dev/null 2>&1
BEFORE=$("$MAC_ABAC_CTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
"$MAC_ABAC_CTL" rule append "$FIXTURES/minimal.rules" >/dev/null 2>&1
AFTER=$("$MAC_ABAC_CTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
if [ "$AFTER" -gt "$BEFORE" ]; then
	pass "append adds to existing rules"
else
	fail "append adds to existing rules (before: $BEFORE, after: $AFTER)"
fi

# ===========================================
# Comments and whitespace tests
# ===========================================
echo ""
info "=== Comments and Whitespace Tests ==="

# Create a temporary test file with various formats
TMPFILE=$(mktemp)
cat > "$TMPFILE" << 'EOF'
# This is a comment
allow exec * -> *

   # Indented comment
   deny exec * -> type=untrusted

# Blank lines above and below

allow read * -> *
# Trailing comment after rules
EOF

run_test
info "Test: Comments and whitespace handled correctly"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule load "$TMPFILE" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 3 rules"; then
	pass "comments and whitespace handled"
else
	fail "comments and whitespace handled (got: $OUTPUT)"
fi

rm -f "$TMPFILE"

# ===========================================
# Clear and reload test
# ===========================================
echo ""
info "=== Clear and Reload Tests ==="

run_test
info "Test: Clear then load"
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
if echo "$OUTPUT" | grep -qi "no rules"; then
	"$MAC_ABAC_CTL" rule load "$FIXTURES/minimal.rules" >/dev/null 2>&1
	OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
	if echo "$OUTPUT" | grep -q "allow"; then
		pass "clear then load"
	else
		fail "clear then load (rules not loaded)"
	fi
else
	fail "clear then load (clear failed)"
fi

# ===========================================
# Summary
# ===========================================

summary
