#!/bin/sh
#
# Test: Label and rule limits
#
# Tests the system limits for labels, keys, values, and rules.
# Verifies the increased limits from the mac_syscall migration work correctly.
#
# Current limits:
#   FILE LABELS (stored in extattr):
#     - Label length: 4096 bytes
#     - Key length: 64 bytes (63 usable)
#     - Value length: 256 bytes (255 usable)
#     - Key-value pairs: 16 per label
#
#   RULE PATTERNS (more compact):
#     - Key length: 64 bytes (63 usable)
#     - Value length: 64 bytes (63 usable)
#     - Key-value pairs: 8 per pattern
#
#   SYSTEM:
#     - Rules: 4096 max
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
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
echo "Label and Rule Limits Tests"
echo "============================================"
echo ""

# Save original state
ORIG_MODE=$("$VLABELCTL" mode)
"$VLABELCTL" mode disabled >/dev/null 2>&1
"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Test: Multiple key-value pairs
# ===========================================
info "=== Key-Value Pair Limits ==="

run_test
info "Test: Rule with 8 key-value pairs (moderate)"
PATTERN_8="k1=v1,k2=v2,k3=v3,k4=v4,k5=v5,k6=v6,k7=v7,k8=v8"
if "$VLABELCTL" rule add "allow read $PATTERN_8 -> $PATTERN_8" >/dev/null 2>&1; then
    pass "8 key-value pairs accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "8 key-value pairs"
fi

# Note: Rule patterns are limited to 8 pairs (VLABEL_RULE_MAX_PAIRS)
# File labels support 16 pairs but rules are more compact

# ===========================================
# Test: Key and value lengths
# ===========================================
info ""
info "=== Key and Value Length Limits ==="

run_test
info "Test: Moderate key length (30 chars)"
KEY_30="keyname_with_thirty_characters"
if "$VLABELCTL" rule add "allow read ${KEY_30}=value -> *" >/dev/null 2>&1; then
    pass "30-char key accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "30-char key"
fi

run_test
info "Test: Long key length (60 chars, under 64 limit)"
KEY_60="this_is_a_very_long_key_name_that_is_sixty_characters_long__"
if "$VLABELCTL" rule add "allow read ${KEY_60}=value -> *" >/dev/null 2>&1; then
    pass "60-char key accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "60-char key"
fi

# Note: Rule pattern values are limited to 64 chars (VLABEL_RULE_VALUE_LEN)
# File labels support 256-char values but rules use shorter values

run_test
info "Test: Moderate value length (50 chars, under 64 rule limit)"
VALUE_50="this_is_a_moderately_long_value_string_that_is_ok"
if "$VLABELCTL" rule add "allow read type=$VALUE_50 -> *" >/dev/null 2>&1; then
    pass "50-char value accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "50-char value"
fi

run_test
info "Test: Max value length (63 chars, at rule limit)"
VALUE_63="this_is_exactly_sixty_three_characters_long_for_rule_patterns__"
if "$VLABELCTL" rule add "allow read type=$VALUE_63 -> *" >/dev/null 2>&1; then
    pass "63-char value accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "63-char value"
fi

# ===========================================
# Test: Multiple rules
# ===========================================
info ""
info "=== Multiple Rules Test ==="

run_test
info "Test: Adding 50 rules"
SUCCESS=1
for i in $(seq 1 50); do
    if ! "$VLABELCTL" rule add "allow read id=$i -> *" >/dev/null 2>&1; then
        SUCCESS=0
        break
    fi
done
if [ $SUCCESS -eq 1 ]; then
    OUTPUT=$("$VLABELCTL" rule list 2>&1)
    if echo "$OUTPUT" | grep -q "Loaded rules: 50"; then
        pass "50 rules added"
    else
        fail "50 rules (count mismatch: $OUTPUT)"
    fi
else
    fail "50 rules (failed at rule $i)"
fi
"$VLABELCTL" rule clear >/dev/null 2>&1

run_test
info "Test: Adding 100 rules"
SUCCESS=1
for i in $(seq 1 100); do
    if ! "$VLABELCTL" rule add "allow read id=$i -> *" >/dev/null 2>&1; then
        SUCCESS=0
        break
    fi
done
if [ $SUCCESS -eq 1 ]; then
    OUTPUT=$("$VLABELCTL" rule list 2>&1)
    if echo "$OUTPUT" | grep -q "Loaded rules: 100"; then
        pass "100 rules added"
    else
        fail "100 rules (count mismatch)"
    fi
else
    fail "100 rules (failed at rule $i)"
fi
"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Test: Complex combined patterns
# ===========================================
info ""
info "=== Complex Pattern Tests ==="

run_test
info "Test: Complex subject and object patterns"
COMPLEX_SUBJ="type=daemon,domain=security,name=auditor,env=prod,tier=backend"
COMPLEX_OBJ="sensitivity=secret,compartment=intel,project=alpha,handling=noforn"
if "$VLABELCTL" rule add "allow read $COMPLEX_SUBJ -> $COMPLEX_OBJ" >/dev/null 2>&1; then
    pass "complex patterns accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "complex patterns"
fi

# ===========================================
# Test: Context fields with label patterns
# ===========================================
info ""
info "=== Context + Pattern Combination Tests ==="

run_test
info "Test: Rule with all context fields + complex patterns"
# Context fields are separate from pattern key=value pairs
# This tests that using many context fields doesn't hit pair limits
PATTERN_WITH_CTX="type=app,domain=secure,tier=prod,env=test"
if "$VLABELCTL" rule add "deny debug $PATTERN_WITH_CTX -> $PATTERN_WITH_CTX subj_context:uid=0,jail=host,has_tty=true obj_context:sandboxed=true,jail=any" >/dev/null 2>&1; then
    pass "all context fields + complex patterns accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "all context fields + complex patterns"
fi

run_test
info "Test: Max pattern pairs (8) with all context fields"
# Rule patterns limited to 8 pairs, but context is separate
PATTERN_8="k1=v1,k2=v2,k3=v3,k4=v4,k5=v5,k6=v6,k7=v7,k8=v8"
if "$VLABELCTL" rule add "deny signal $PATTERN_8 -> $PATTERN_8 subj_context:uid=0,gid=0,jail=host obj_context:sandboxed=true" >/dev/null 2>&1; then
    pass "8 pattern pairs + all contexts accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "8 pattern pairs + all contexts"
fi

run_test
info "Test: Rule with both subj_context and obj_context"
if "$VLABELCTL" rule add "deny sched type=a -> type=b subj_context:jail=any obj_context:jail=host" >/dev/null 2>&1; then
    pass "dual context constraints accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "dual context constraints"
fi

run_test
info "Test: Transition rule with complex newlabel"
COMPLEX_NEWLABEL="type=elevated,domain=system,privileges=admin,audit=required,timestamp=now"
if "$VLABELCTL" rule add "transition exec * -> type=setuid => $COMPLEX_NEWLABEL" >/dev/null 2>&1; then
    pass "complex transition rule accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "complex transition rule"
fi

# ===========================================
# Test: Test access with complex labels
# ===========================================
info ""
info "=== Test Access with Complex Labels ==="

"$VLABELCTL" rule add "deny read sensitivity=topsecret -> *" >/dev/null 2>&1
"$VLABELCTL" rule add "allow read clearance=secret -> sensitivity=secret" >/dev/null 2>&1
"$VLABELCTL" rule add "allow read * -> *" >/dev/null 2>&1
"$VLABELCTL" default allow >/dev/null 2>&1

run_test
info "Test: Complex label matching - deny"
OUTPUT=$("$VLABELCTL" test read "sensitivity=topsecret,compartment=sci" "sensitivity=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "complex deny match"
else
    fail "complex deny match (got: $OUTPUT)"
fi

run_test
info "Test: Complex label matching - allow"
OUTPUT=$("$VLABELCTL" test read "clearance=secret,department=intel" "sensitivity=secret,project=alpha" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "complex allow match"
else
    fail "complex allow match (got: $OUTPUT)"
fi

"$VLABELCTL" rule clear >/dev/null 2>&1

# ===========================================
# Restore original settings
# ===========================================
info ""
info "Restoring original settings..."
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
