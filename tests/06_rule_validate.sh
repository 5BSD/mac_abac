#!/bin/sh
#
# Test: Rule validation (vlabelctl rule validate)
#
# Tests the rule validation feature which checks rules without loading
# them into the kernel.
#
# Prerequisites:
# - vlabelctl must be built
# - Does NOT require module to be loaded (validation is local)
#
# Usage:
#   ./06_rule_validate.sh [path_to_vlabelctl]
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
FIXTURES="$SCRIPT_DIR/fixtures/policies"

# Check prerequisites
if [ ! -x "$VLABELCTL" ]; then
	echo "vlabelctl not found or not executable: $VLABELCTL"
	exit 1
fi

if [ ! -d "$FIXTURES" ]; then
	echo "Fixtures directory not found: $FIXTURES"
	exit 1
fi

echo "============================================"
echo "Rule Validation Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Using fixtures: $FIXTURES"
echo ""

# ===========================================
# Single rule validation - valid rules
# ===========================================
info "=== Single Rule Validation (Valid) ==="

run_test
info "Test: Valid simple allow rule"
OUTPUT=$("$VLABELCTL" rule validate "allow exec * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid simple allow rule"
else
	fail "valid simple allow rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid deny rule"
OUTPUT=$("$VLABELCTL" rule validate "deny exec * -> type=untrusted" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid deny rule"
else
	fail "valid deny rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid transition rule with newlabel"
OUTPUT=$("$VLABELCTL" rule validate "transition exec * -> type=app => type=daemon" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid transition rule"
else
	fail "valid transition rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid rule with context constraint"
OUTPUT=$("$VLABELCTL" rule validate "allow exec * -> type=admin context:uid=0" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid context rule"
else
	fail "valid context rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid multi-operation rule"
OUTPUT=$("$VLABELCTL" rule validate "allow read,write,mmap * -> domain=web" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid multi-operation rule"
else
	fail "valid multi-operation rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid negation pattern"
OUTPUT=$("$VLABELCTL" rule validate "deny exec * -> !type=trusted" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid negation pattern"
else
	fail "valid negation pattern (got: $OUTPUT)"
fi

run_test
info "Test: Valid complex pattern"
OUTPUT=$("$VLABELCTL" rule validate "allow read type=app,domain=web -> type=data,sensitivity=public" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid complex pattern"
else
	fail "valid complex pattern (got: $OUTPUT)"
fi

# ===========================================
# Single rule validation - invalid rules
# ===========================================
echo ""
info "=== Single Rule Validation (Invalid) ==="

run_test
info "Test: Missing arrow separator"
OUTPUT=$("$VLABELCTL" rule validate "deny exec * type=untrusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "missing arrow rejected"
else
	fail "missing arrow rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid action"
OUTPUT=$("$VLABELCTL" rule validate "permit exec * -> *" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "invalid action rejected"
else
	fail "invalid action rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid operation"
OUTPUT=$("$VLABELCTL" rule validate "deny foo * -> *" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "invalid operation rejected"
else
	fail "invalid operation rejected (got: $OUTPUT)"
fi

run_test
info "Test: Garbage input"
OUTPUT=$("$VLABELCTL" rule validate "this is not a rule at all" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "garbage rejected"
else
	fail "garbage rejected (got: $OUTPUT)"
fi

run_test
info "Test: Empty rule"
OUTPUT=$("$VLABELCTL" rule validate "" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "empty rule rejected"
else
	fail "empty rule rejected (got: $OUTPUT)"
fi

# ===========================================
# Transition warnings
# ===========================================
echo ""
info "=== Transition Warnings ==="

run_test
info "Test: Transition without newlabel generates warning"
OUTPUT=$("$VLABELCTL" rule validate "transition exec * -> type=app" 2>&1)
if echo "$OUTPUT" | grep -q "WARNING"; then
	pass "transition without newlabel warns"
else
	fail "transition without newlabel warns (got: $OUTPUT)"
fi

# ===========================================
# File validation - valid file
# ===========================================
echo ""
info "=== File Validation ==="

run_test
info "Test: Validate valid_complete.rules"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/valid_complete.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "valid_complete.rules passes"
else
	fail "valid_complete.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate minimal.rules"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/minimal.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "minimal.rules passes"
else
	fail "minimal.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate web_sandbox.rules"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/web_sandbox.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "web_sandbox.rules passes"
else
	fail "web_sandbox.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate multi_tenant.rules"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/multi_tenant.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "multi_tenant.rules passes"
else
	fail "multi_tenant.rules passes (got: $OUTPUT)"
fi

# ===========================================
# File validation - invalid file
# ===========================================
echo ""
info "=== File Validation (Errors) ==="

run_test
info "Test: Validate invalid_syntax.rules detects errors"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/invalid_syntax.rules" 2>&1 || true)
if echo "$OUTPUT" | grep "errors" | grep -v "0 errors" >/dev/null; then
	pass "invalid_syntax.rules detects errors"
else
	fail "invalid_syntax.rules detects errors (got: $OUTPUT)"
fi

run_test
info "Test: Validate warnings.rules detects warnings"
OUTPUT=$("$VLABELCTL" rule validate -f "$FIXTURES/warnings.rules" 2>&1 || true)
if echo "$OUTPUT" | grep -q "warnings" && echo "$OUTPUT" | grep -v "0 warnings" >/dev/null; then
	pass "warnings.rules detects warnings"
else
	fail "warnings.rules detects warnings (got: $OUTPUT)"
fi

# ===========================================
# File validation - edge cases
# ===========================================
echo ""
info "=== File Validation (Edge Cases) ==="

run_test
info "Test: Non-existent file fails"
if "$VLABELCTL" rule validate -f "/nonexistent/file.rules" >/dev/null 2>&1; then
	fail "non-existent file fails"
else
	pass "non-existent file fails"
fi

# ===========================================
# All operations valid
# ===========================================
echo ""
info "=== All Operations Valid ==="

run_test
info "Test: All operations accepted"
ALL_VALID=1
for op in exec read write mmap link rename unlink chdir stat readdir create open access lookup setextattr getextattr debug signal sched all; do
	OUTPUT=$("$VLABELCTL" rule validate "allow $op * -> *" 2>&1)
	if ! echo "$OUTPUT" | grep -q "OK"; then
		warn "Operation '$op' not accepted"
		ALL_VALID=0
	fi
done
if [ $ALL_VALID -eq 1 ]; then
	pass "all operations valid"
else
	fail "all operations valid"
fi

# ===========================================
# Summary
# ===========================================

summary
