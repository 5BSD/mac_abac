#!/bin/sh
#
# Test: Label and rule limits
#
# Tests the system limits for labels, keys, values, and rules.
# Verifies the increased limits from the mac_syscall migration work correctly.
#
# Current limits:
#   - Label length: 4096 bytes
#   - Key length: 64 bytes
#   - Value length: 256 bytes
#   - Key-value pairs: 16 per label
#   - Rules: 1024 max
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

run_test
info "Test: Rule with 16 key-value pairs (maximum)"
PATTERN_16="k01=v01,k02=v02,k03=v03,k04=v04,k05=v05,k06=v06,k07=v07,k08=v08,k09=v09,k10=v10,k11=v11,k12=v12,k13=v13,k14=v14,k15=v15,k16=v16"
if "$VLABELCTL" rule add "allow read $PATTERN_16 -> *" >/dev/null 2>&1; then
    pass "16 key-value pairs accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "16 key-value pairs"
fi

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

run_test
info "Test: Moderate value length (100 chars)"
VALUE_100="this_is_a_moderately_long_value_string_that_should_be_accepted_by_the_system_without_any_problems___"
if "$VLABELCTL" rule add "allow read type=$VALUE_100 -> *" >/dev/null 2>&1; then
    pass "100-char value accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "100-char value"
fi

run_test
info "Test: Long value length (200 chars, under 256 limit)"
VALUE_200="this_is_a_very_long_value_string_that_tests_the_increased_limit_of_256_characters_per_value_which_should_now_be_possible_with_the_mac_syscall_interface_that_replaced_the_old_ioctl_device_interface____"
if "$VLABELCTL" rule add "allow read type=$VALUE_200 -> *" >/dev/null 2>&1; then
    pass "200-char value accepted"
    "$VLABELCTL" rule clear >/dev/null 2>&1
else
    fail "200-char value"
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
