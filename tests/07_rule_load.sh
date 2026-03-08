#!/bin/sh
#
# Test: Rule loading from file (vlabelctl rule load)
#
# Tests the rule load feature which loads multiple rules from a file.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
#
# Usage:
#   ./07_rule_load.sh [path_to_vlabelctl]
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration - find vlabelctl relative to script location
if [ -n "$1" ]; then
	VLABELCTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/vlabelctl" ]; then
	VLABELCTL="$SCRIPT_DIR/../tools/vlabelctl"
else
	VLABELCTL="./tools/vlabelctl"
fi
MODULE_NAME="mac_vlabel"
FIXTURES="$SCRIPT_DIR/fixtures/policies"

# Check prerequisites
require_root
require_vlabelctl

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
	"$VLABELCTL" rule clear >/dev/null 2>&1 || true
}

echo "============================================"
echo "Rule Load Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Using fixtures: $FIXTURES"
echo ""

# Clear any existing rules
"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Basic load tests
# ===========================================
info "=== Basic Load Tests ==="

run_test
info "Test: Load minimal.rules"
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule load "$FIXTURES/minimal.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 1 rules"; then
	pass "load minimal.rules"
else
	fail "load minimal.rules (got: $OUTPUT)"
fi

run_test
info "Test: Verify rule was loaded"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "allow"; then
	pass "rule appears in list"
else
	fail "rule appears in list (got: $OUTPUT)"
fi

run_test
info "Test: Load web_sandbox.rules"
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule load "$FIXTURES/web_sandbox.rules" 2>&1)
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
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule load "$FIXTURES/multi_tenant.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	pass "load multi_tenant.rules"
else
	fail "load multi_tenant.rules (got: $OUTPUT)"
fi

run_test
info "Test: Load valid_complete.rules"
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule load "$FIXTURES/valid_complete.rules" 2>&1)
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
"$VLABELCTL" rule clear >/dev/null 2>&1 || true
OUTPUT=$("$VLABELCTL" rule load "$FIXTURES/invalid_syntax.rules" 2>&1 || true)
if echo "$OUTPUT" | grep -q "errors"; then
	pass "invalid file reports errors"
else
	fail "invalid file reports errors (got: $OUTPUT)"
fi

run_test
info "Test: Some valid rules still loaded from invalid file"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "allow\|deny"; then
	pass "valid rules from invalid file loaded"
else
	fail "valid rules from invalid file loaded (got: $OUTPUT)"
fi

run_test
info "Test: Non-existent file fails"
if "$VLABELCTL" rule load "/nonexistent/file.rules" >/dev/null 2>&1; then
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
info "Test: Load appends to existing rules"
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" rule add "deny exec * -> type=first" >/dev/null 2>&1
BEFORE=$("$VLABELCTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
"$VLABELCTL" rule load "$FIXTURES/minimal.rules" >/dev/null 2>&1
AFTER=$("$VLABELCTL" rule list 2>&1 | grep "Loaded rules" | grep -o '[0-9]*')
if [ "$AFTER" -gt "$BEFORE" ]; then
	pass "load appends to existing rules"
else
	fail "load appends to existing rules (before: $BEFORE, after: $AFTER)"
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
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule load "$TMPFILE" 2>&1)
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
"$VLABELCTL" rule clear >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -qi "no rules"; then
	"$VLABELCTL" rule load "$FIXTURES/minimal.rules" >/dev/null 2>&1
	OUTPUT=$("$VLABELCTL" rule list 2>&1)
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
