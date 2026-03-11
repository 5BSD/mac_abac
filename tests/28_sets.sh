#!/bin/sh
#
# Test: Rule Sets
#
# Tests IPFW-style rule sets for grouping and bulk enable/disable.
#
# Prerequisites:
# - mac_abac_ctl must be built
# - Does NOT require module to be loaded (validation is local)
#
# Usage:
#   ./28_sets.sh [path_to_mac_abac_ctl]
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration - find mac_abac_ctl
MAC_ABAC_CTL="${1:-$(find_mac_abac_ctl)}"

# Check prerequisites
if [ ! -x "$MAC_ABAC_CTL" ]; then
	echo "mac_abac_ctl not found or not executable: $MAC_ABAC_CTL"
	exit 1
fi

echo "============================================"
echo "Rule Sets Tests"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
echo ""

# ===========================================
# Basic set syntax in line format
# ===========================================
info "=== Set Syntax (Line Format) ==="

run_test
info "Test: Rule with 'set 0' (default)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 0" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set 0 accepted"
else
	fail "set 0 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Rule with 'set 1'"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 1" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set 1 accepted"
else
	fail "set 1 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Rule with 'set 100'"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny read * -> type=secret set 100" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set 100 accepted"
else
	fail "set 100 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Rule with high set number (65000)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow write * -> * set 65000" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set 65000 accepted"
else
	fail "set 65000 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Rule with max valid set (65535)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 65535" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set 65535 accepted"
else
	fail "set 65535 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Rule without set (defaults to 0)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "rule without set accepted (defaults to 0)"
else
	fail "rule without set accepted (got: $OUTPUT)"
fi

# ===========================================
# Invalid set numbers
# ===========================================
echo ""
info "=== Invalid Set Numbers ==="

run_test
info "Test: Invalid set (65536 - too large)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 65536" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR\|invalid set"; then
	pass "set 65536 rejected"
else
	fail "set 65536 rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid set (100000 - too large)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 100000" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR\|invalid set"; then
	pass "set 100000 rejected"
else
	fail "set 100000 rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid set (negative)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set -1" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR\|invalid set"; then
	pass "negative set rejected"
else
	fail "negative set rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid set (non-numeric)"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set abc" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR\|invalid set"; then
	pass "non-numeric set rejected"
else
	fail "non-numeric set rejected (got: $OUTPUT)"
fi

run_test
info "Test: Missing set number"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ERROR\|missing set"; then
	pass "missing set number rejected"
else
	fail "missing set number rejected (got: $OUTPUT)"
fi

# ===========================================
# Set with other modifiers
# ===========================================
echo ""
info "=== Set Combined With Other Modifiers ==="

run_test
info "Test: Set with context"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> type=app ctx:uid=0 set 5" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set with context accepted"
else
	fail "set with context accepted (got: $OUTPUT)"
fi

run_test
info "Test: Set with complex pattern"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow read,write type=app,domain=web -> type=data,sensitivity=public set 10" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set with complex pattern accepted"
else
	fail "set with complex pattern accepted (got: $OUTPUT)"
fi

run_test
info "Test: Transition rule with set"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "transition exec * -> type=app => type=daemon set 20" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "transition with set accepted"
else
	fail "transition with set accepted (got: $OUTPUT)"
fi

run_test
info "Test: Set with negation"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny exec * -> !type=trusted set 15" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set with negation accepted"
else
	fail "set with negation accepted (got: $OUTPUT)"
fi

# ===========================================
# Set ordering in rule specification
# ===========================================
echo ""
info "=== Set Position in Rule ==="

run_test
info "Test: Set at end of rule"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 5" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "set at end accepted"
else
	fail "set at end accepted (got: $OUTPUT)"
fi

run_test
info "Test: Context then set"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "deny write * -> * ctx:jail=host set 30" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "context then set accepted"
else
	fail "context then set accepted (got: $OUTPUT)"
fi

# ===========================================
# UCL format set field tests
# ===========================================
echo ""
info "=== UCL Format (via mac_abac_ctl set list) ==="

# Note: UCL tests require module or we test via help output
run_test
info "Test: mac_abac_ctl set help shows commands"
OUTPUT=$("$MAC_ABAC_CTL" set 2>&1 || true)
if echo "$OUTPUT" | grep -q "enable\|disable\|swap"; then
	pass "mac_abac_ctl set shows subcommands"
else
	fail "mac_abac_ctl set shows subcommands (got: $OUTPUT)"
fi

run_test
info "Test: mac_abac_ctl set enable requires argument"
OUTPUT=$("$MAC_ABAC_CTL" set enable 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires\|usage"; then
	pass "set enable requires argument"
else
	fail "set enable requires argument (got: $OUTPUT)"
fi

run_test
info "Test: mac_abac_ctl set disable requires argument"
OUTPUT=$("$MAC_ABAC_CTL" set disable 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires\|usage"; then
	pass "set disable requires argument"
else
	fail "set disable requires argument (got: $OUTPUT)"
fi

run_test
info "Test: mac_abac_ctl set swap requires two arguments"
OUTPUT=$("$MAC_ABAC_CTL" set swap 5 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires\|two\|usage"; then
	pass "set swap requires two arguments"
else
	fail "set swap requires two arguments (got: $OUTPUT)"
fi

run_test
info "Test: mac_abac_ctl set move requires two arguments"
OUTPUT=$("$MAC_ABAC_CTL" set move 5 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires\|two\|usage"; then
	pass "set move requires two arguments"
else
	fail "set move requires two arguments (got: $OUTPUT)"
fi

run_test
info "Test: mac_abac_ctl set clear requires argument"
OUTPUT=$("$MAC_ABAC_CTL" set clear 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires\|usage"; then
	pass "set clear requires argument"
else
	fail "set clear requires argument (got: $OUTPUT)"
fi

run_test
info "Test: Unknown set subcommand rejected"
OUTPUT=$("$MAC_ABAC_CTL" set badcommand 2>&1 || true)
if echo "$OUTPUT" | grep -q "unknown\|usage"; then
	pass "unknown set subcommand rejected"
else
	fail "unknown set subcommand rejected (got: $OUTPUT)"
fi

# ===========================================
# Range syntax validation
# ===========================================
echo ""
info "=== Set Range Syntax ==="

run_test
info "Test: Invalid range (start > end)"
OUTPUT=$("$MAC_ABAC_CTL" set enable 10-5 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid\|error\|Error"; then
	pass "invalid range (start > end) rejected"
else
	fail "invalid range (start > end) rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid range format"
OUTPUT=$("$MAC_ABAC_CTL" set enable 5- 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid\|error\|Error"; then
	pass "invalid range format rejected"
else
	fail "invalid range format rejected (got: $OUTPUT)"
fi

run_test
info "Test: Invalid set in range (too large)"
OUTPUT=$("$MAC_ABAC_CTL" set enable 0-70000 2>&1 || true)
if echo "$OUTPUT" | grep -q "invalid\|error\|Error"; then
	pass "set range with too large end rejected"
else
	fail "set range with too large end rejected (got: $OUTPUT)"
fi

# ===========================================
# Edge cases
# ===========================================
echo ""
info "=== Edge Cases ==="

run_test
info "Test: Boundary set 0"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> * set 0" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "boundary set 0 accepted"
else
	fail "boundary set 0 accepted (got: $OUTPUT)"
fi

run_test
info "Test: Multiple spaces before set"
OUTPUT=$("$MAC_ABAC_CTL" rule validate "allow exec * -> *    set 5" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
	pass "multiple spaces before set accepted"
else
	fail "multiple spaces before set accepted (got: $OUTPUT)"
fi

# ===========================================
# Summary
# ===========================================

summary
