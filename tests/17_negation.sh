#!/bin/sh
#
# Test: Negation Pattern Matching
#
# Tests that negation patterns (!pattern) work correctly for both
# subject and object patterns in all supported scenarios.
#
# Negation can be used on:
# - Subject patterns: !type=restricted -> *
# - Object patterns: * -> !type=untrusted
# - Both: !type=restricted -> !type=untrusted
#
# Negation CANNOT be used on:
# - Context constraints (subj_context:, obj_context:)
# - Newlabel in transition rules
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
if [ -n "$1" ]; then
	VLABELCTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/vlabelctl" ]; then
	VLABELCTL="$SCRIPT_DIR/../tools/vlabelctl"
else
	VLABELCTL="./tools/vlabelctl"
fi

MODULE_NAME="mac_vlabel"

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	"$VLABELCTL" mode permissive >/dev/null 2>&1 || true
	"$VLABELCTL" rule clear >/dev/null 2>&1 || true
	"$VLABELCTL" default allow >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "============================================"
echo "Negation Pattern Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# ===========================================
# Part 1: Syntax Validation Tests
# ===========================================
info "=== Syntax Validation ==="

run_test
info "Test: Negated object pattern parses"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny exec * -> !type=trusted" >/dev/null 2>&1; then
	pass "negated object pattern"
else
	fail "negated object pattern"
fi

run_test
info "Test: Negated subject pattern parses"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny exec !type=admin -> *" >/dev/null 2>&1; then
	pass "negated subject pattern"
else
	fail "negated subject pattern"
fi

run_test
info "Test: Both patterns negated parses"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny exec !type=trusted -> !type=public" >/dev/null 2>&1; then
	pass "both patterns negated"
else
	fail "both patterns negated"
fi

run_test
info "Test: Negated multi-key pattern parses"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny exec * -> !type=user,domain=web" >/dev/null 2>&1; then
	pass "negated multi-key pattern"
else
	fail "negated multi-key pattern"
fi

run_test
info "Test: Negated wildcard parses (!*)"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny exec * -> !*" >/dev/null 2>&1; then
	# !* means "NOT match anything" = match nothing = rule never triggers
	pass "negated wildcard (!*)"
else
	fail "negated wildcard (!*)"
fi

# ===========================================
# Part 2: Rule List Display Tests
# ===========================================
echo ""
info "=== Rule List Display ==="

run_test
info "Test: Negated patterns display correctly in rule list"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny exec !type=admin -> !type=public" >/dev/null 2>&1
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "!type=admin" && echo "$OUTPUT" | grep -q "!type=public"; then
	pass "negation displayed in rule list"
else
	fail "negation displayed in rule list (got: $OUTPUT)"
fi

# ===========================================
# Part 3: Test Command (vlabelctl test)
# ===========================================
echo ""
info "=== Test Command Verification ==="

# Test: deny exec * -> !type=trusted
# Should DENY if object is NOT type=trusted (i.e., deny anything except trusted)
run_test
info "Test: Object negation - DENY non-trusted"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny exec * -> !type=trusted" >/dev/null
# type=untrusted should be DENIED (it's not trusted)
# Note: vlabelctl test returns non-zero on DENY, use || true to capture output
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=untrusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "deny non-trusted object"
else
	fail "deny non-trusted object (got: $OUTPUT)"
fi

run_test
info "Test: Object negation - ALLOW trusted"
# type=trusted should be ALLOWED (negation doesn't match)
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=trusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "allow trusted object"
else
	fail "allow trusted object (got: $OUTPUT)"
fi

# Test: allow exec !type=restricted -> *
# Should ALLOW if subject is NOT type=restricted
run_test
info "Test: Subject negation - ALLOW non-restricted"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "allow exec !type=restricted -> *" >/dev/null
"$VLABELCTL" default deny >/dev/null
# type=user should be ALLOWED (it's not restricted)
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "allow non-restricted subject"
else
	fail "allow non-restricted subject (got: $OUTPUT)"
fi

run_test
info "Test: Subject negation - DEFAULT for restricted"
# type=restricted should NOT match the rule (falls through to default deny)
OUTPUT=$("$VLABELCTL" test exec "type=restricted" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "restricted subject falls to default"
else
	fail "restricted subject falls to default (got: $OUTPUT)"
fi

# Reset default
"$VLABELCTL" default allow >/dev/null

# ===========================================
# Part 4: Complex Negation Scenarios
# ===========================================
echo ""
info "=== Complex Scenarios ==="

# Scenario: Allow all EXCEPT restricted->secret
# Rule: deny exec type=restricted -> type=secret
# Then: allow exec * -> *
run_test
info "Test: Positive deny before catch-all allow"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny exec type=restricted -> type=secret" >/dev/null
"$VLABELCTL" rule add "allow exec * -> *" >/dev/null
OUTPUT=$("$VLABELCTL" test exec "type=restricted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "positive deny works"
else
	fail "positive deny works (got: $OUTPUT)"
fi

# Scenario: Deny everything EXCEPT trusted->trusted
# Rule: allow exec type=trusted -> type=trusted
# Default: deny
run_test
info "Test: Allow exception with deny default"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "allow exec type=trusted -> type=trusted" >/dev/null
"$VLABELCTL" default deny >/dev/null
OUTPUT=$("$VLABELCTL" test exec "type=trusted" "type=trusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "trusted->trusted allowed"
else
	fail "trusted->trusted allowed (got: $OUTPUT)"
fi

OUTPUT=$("$VLABELCTL" test exec "type=user" "type=trusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "non-trusted subject denied"
else
	fail "non-trusted subject denied (got: $OUTPUT)"
fi

# Reset
"$VLABELCTL" default allow >/dev/null

# Scenario: Double negation - allow !restricted -> !secret
# Should allow anything EXCEPT restricted subjects accessing secret objects
run_test
info "Test: Double negation - allow !restricted -> !secret"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "allow exec !type=restricted -> !type=secret" >/dev/null
"$VLABELCTL" default deny >/dev/null

# user -> public: both negations match, ALLOW
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=public" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "user->public allowed"
else
	fail "user->public allowed (got: $OUTPUT)"
fi

# restricted -> public: subject negation doesn't match, falls to default DENY
OUTPUT=$("$VLABELCTL" test exec "type=restricted" "type=public" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "restricted->public denied"
else
	fail "restricted->public denied (got: $OUTPUT)"
fi

# user -> secret: object negation doesn't match, falls to default DENY
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "user->secret denied"
else
	fail "user->secret denied (got: $OUTPUT)"
fi

# restricted -> secret: neither negation matches, falls to default DENY
OUTPUT=$("$VLABELCTL" test exec "type=restricted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "restricted->secret denied"
else
	fail "restricted->secret denied (got: $OUTPUT)"
fi

# Reset
"$VLABELCTL" default allow >/dev/null

# ===========================================
# Part 5: Negation with Multi-Key Patterns
# ===========================================
echo ""
info "=== Multi-Key Negation ==="

run_test
info "Test: Negated multi-key pattern"
"$VLABELCTL" rule clear >/dev/null
# Deny if object does NOT have both type=trusted AND domain=system
"$VLABELCTL" rule add "deny exec * -> !type=trusted,domain=system" >/dev/null
"$VLABELCTL" rule add "allow exec * -> *" >/dev/null

# Object with only type=trusted (missing domain=system) - negation matches, DENY
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=trusted" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "partial match causes deny"
else
	fail "partial match causes deny (got: $OUTPUT)"
fi

# Object with both type=trusted,domain=system - negation doesn't match, ALLOW
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=trusted,domain=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "full match allows"
else
	fail "full match allows (got: $OUTPUT)"
fi

# ===========================================
# Part 6: Edge Cases
# ===========================================
echo ""
info "=== Edge Cases ==="

run_test
info "Test: Negation of empty/unlabeled"
"$VLABELCTL" rule clear >/dev/null
# Deny access to anything that is NOT type=labeled
"$VLABELCTL" rule add "deny exec * -> !type=labeled" >/dev/null
"$VLABELCTL" rule add "allow exec * -> *" >/dev/null

# Empty label (unlabeled file) - negation matches, DENY
OUTPUT=$("$VLABELCTL" test exec "type=user" "" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "empty label causes negation match"
else
	fail "empty label causes negation match (got: $OUTPUT)"
fi

run_test
info "Test: Negated wildcard (!*) matches nothing"
"$VLABELCTL" rule clear >/dev/null
# !* means NOT(match anything) = match nothing
"$VLABELCTL" rule add "deny exec * -> !*" >/dev/null
"$VLABELCTL" rule add "allow exec * -> *" >/dev/null

# Any object should NOT trigger the deny rule (rule pattern can't match)
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=anything" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "!* matches nothing"
else
	fail "!* matches nothing (got: $OUTPUT)"
fi

# ===========================================
# Summary
# ===========================================

summary
