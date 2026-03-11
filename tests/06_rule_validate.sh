#!/bin/sh
#
# Test: Rule validation (mac_abac_ctl rule validate)
#
# Tests the rule validation feature which checks rules without loading
# them into the kernel.
#
# Prerequisites:
# - mac_abac_ctl must be built
# - Does NOT require module to be loaded (validation is local)
#
# Usage:
#   ./06_rule_validate.sh [path_to_mac_abac_ctl]
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
FIXTURES="$SCRIPT_DIR/fixtures/policies"

# Check prerequisites
if [ ! -x "$MAC_ABAC_CTL" ]; then
	echo "mac_abac_ctl not found or not executable: $MAC_ABAC_CTL"
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
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
info "Using fixtures: $FIXTURES"
echo ""

# ===========================================
# Single rule validation - valid rules
# ===========================================
info "=== Single Rule Validation (Valid) ==="

run_test
info "Test: Valid simple allow rule"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid simple allow rule"
else
	fail "valid simple allow rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid deny rule"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> type=untrusted" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid deny rule"
else
	fail "valid deny rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid transition rule with newlabel"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "transition exec * -> type=app => type=daemon" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid transition rule"
else
	fail "valid transition rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid rule with context constraint"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> type=admin ctx:uid=0" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid context rule"
else
	fail "valid context rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid multi-operation rule"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow read,write,mmap * -> domain=web" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid multi-operation rule"
else
	fail "valid multi-operation rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid negation pattern"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> !type=trusted" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "valid negation pattern"
else
	fail "valid negation pattern (got: $OUTPUT)"
fi

run_test
info "Test: Valid complex pattern"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow read type=app,domain=web -> type=data,sensitivity=public" 2>&1)
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
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * type=untrusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "missing arrow rejected"
else
	fail "missing arrow rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid action"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "permit exec * -> *" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "invalid action rejected"
else
	fail "invalid action rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid operation"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny foo * -> *" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "invalid operation rejected"
else
	fail "invalid operation rejected (got: $OUTPUT)"
fi

run_test
info "Test: Garbage input"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "this is not a rule at all" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "garbage rejected"
else
	fail "garbage rejected (got: $OUTPUT)"
fi

run_test
info "Test: Empty rule"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR"; then
	pass "empty rule rejected"
else
	fail "empty rule rejected (got: $OUTPUT)"
fi

# ===========================================
# Context validation
# ===========================================
echo ""
info "=== Context Validation ==="

run_test
info "Test: Unknown context key"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> * ctx:badkey=value" 2>&1 || true)
if echo "$OUTPUT" | grep -q "unknown context key"; then
	pass "unknown context key rejected"
else
	fail "unknown context key rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid uid value"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> * ctx:uid=notanumber" 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid uid"; then
	pass "invalid uid rejected"
else
	fail "invalid uid rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid sandboxed value"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> * ctx:sandboxed=maybe" 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid sandboxed"; then
	pass "invalid sandboxed value rejected"
else
	fail "invalid sandboxed value rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid jail value"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> * ctx:jail=badvalue" 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid jail"; then
	pass "invalid jail value rejected"
else
	fail "invalid jail value rejected (got: $OUTPUT)"
fi

run_test
info "Test: Empty context"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> * ctx:" 2>&1 || true)
if echo "$OUTPUT" | grep -q "empty context\|ERROR"; then
	pass "empty context rejected"
else
	fail "empty context rejected (got: $OUTPUT)"
fi

run_test
info "Test: Valid context combinations"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * ctx:uid=0,jail=host -> * ctx:sandboxed=true" 2>&1)
if echo "$OUTPUT" | grep -q "^OK"; then
	pass "valid context combinations accepted"
else
	fail "valid context combinations accepted (got: $OUTPUT)"
fi

# ===========================================
# Transition warnings
# ===========================================
echo ""
info "=== Transition Warnings ==="

run_test
info "Test: Transition without newlabel generates warning"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "transition exec * -> type=app" 2>&1)
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
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/valid_complete.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "valid_complete.rules passes"
else
	fail "valid_complete.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate minimal.rules"
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/minimal.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "minimal.rules passes"
else
	fail "minimal.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate web_sandbox.rules"
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/web_sandbox.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
	pass "web_sandbox.rules passes"
else
	fail "web_sandbox.rules passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate multi_tenant.rules"
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/multi_tenant.rules" 2>&1)
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
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/invalid_syntax.rules" 2>&1 || true)
if echo "$OUTPUT" | grep "errors" | grep -v "0 errors" >/dev/null; then
	pass "invalid_syntax.rules detects errors"
else
	fail "invalid_syntax.rules detects errors (got: $OUTPUT)"
fi

run_test
info "Test: Validate warnings.rules detects warnings"
OUTPUT=$("$MAC_ABAC_CTL" rule validate -f "$FIXTURES/warnings.rules" 2>&1 || true)
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
if "$MAC_ABAC_CTL" rule validate -f "/nonexistent/file.rules" >/dev/null 2>&1; then
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
	OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow $op * -> *" 2>&1)
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
