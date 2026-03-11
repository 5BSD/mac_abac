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
# - mac_abac_ctl must be built
#

set -e

# Configuration
MAC_ABAC_CTL="${1:-$(find_mac_abac_ctl)}"
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
    echo "Module not loaded. Please load the module first."
    exit 1
fi

echo "============================================"
echo "Label and Rule Limits Tests"
echo "============================================"
echo ""

# Save original state
ORIG_MODE=$("$MAC_ABAC_CTL" mode)
"$MAC_ABAC_CTL" mode disabled >/dev/null 2>&1
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

# ===========================================
# Test: Multiple key-value pairs
# ===========================================
info "=== Key-Value Pair Limits ==="

run_test
info "Test: Rule with 8 key-value pairs (moderate)"
PATTERN_8="k1=v1,k2=v2,k3=v3,k4=v4,k5=v5,k6=v6,k7=v7,k8=v8"
if "$MAC_ABAC_CTL" rule add "allow read $PATTERN_8 -> $PATTERN_8" >/dev/null 2>&1; then
    pass "8 key-value pairs accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "8 key-value pairs"
fi

# Note: Rule patterns are limited to 8 pairs (ABAC_RULE_MAX_PAIRS)
# File labels support 16 pairs but rules are more compact

# ===========================================
# Test: Key and value lengths
# ===========================================
info ""
info "=== Key and Value Length Limits ==="

run_test
info "Test: Moderate key length (30 chars)"
KEY_30="keyname_with_thirty_characters"
if "$MAC_ABAC_CTL" rule add "allow read ${KEY_30}=value -> *" >/dev/null 2>&1; then
    pass "30-char key accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "30-char key"
fi

run_test
info "Test: Long key length (60 chars, under 64 limit)"
KEY_60="this_is_a_very_long_key_name_that_is_sixty_characters_long__"
if "$MAC_ABAC_CTL" rule add "allow read ${KEY_60}=value -> *" >/dev/null 2>&1; then
    pass "60-char key accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "60-char key"
fi

# Note: Rule pattern values are limited to 64 chars (ABAC_RULE_VALUE_LEN)
# File labels support 256-char values but rules use shorter values

run_test
info "Test: Moderate value length (50 chars, under 64 rule limit)"
VALUE_50="this_is_a_moderately_long_value_string_that_is_ok"
if "$MAC_ABAC_CTL" rule add "allow read type=$VALUE_50 -> *" >/dev/null 2>&1; then
    pass "50-char value accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "50-char value"
fi

run_test
info "Test: Max value length (63 chars, at rule limit)"
VALUE_63="this_is_exactly_sixty_three_characters_long_for_rule_patterns__"
if "$MAC_ABAC_CTL" rule add "allow read type=$VALUE_63 -> *" >/dev/null 2>&1; then
    pass "63-char value accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
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
    if ! "$MAC_ABAC_CTL" rule add "allow read id=$i -> *" >/dev/null 2>&1; then
        SUCCESS=0
        break
    fi
done
if [ $SUCCESS -eq 1 ]; then
    OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
    if echo "$OUTPUT" | grep -q "Loaded rules: 50"; then
        pass "50 rules added"
    else
        fail "50 rules (count mismatch: $OUTPUT)"
    fi
else
    fail "50 rules (failed at rule $i)"
fi
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

run_test
info "Test: Adding 100 rules"
SUCCESS=1
for i in $(seq 1 100); do
    if ! "$MAC_ABAC_CTL" rule add "allow read id=$i -> *" >/dev/null 2>&1; then
        SUCCESS=0
        break
    fi
done
if [ $SUCCESS -eq 1 ]; then
    OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
    if echo "$OUTPUT" | grep -q "Loaded rules: 100"; then
        pass "100 rules added"
    else
        fail "100 rules (count mismatch)"
    fi
else
    fail "100 rules (failed at rule $i)"
fi
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

# ===========================================
# Test: Complex combined patterns
# ===========================================
info ""
info "=== Complex Pattern Tests ==="

run_test
info "Test: Complex subject and object patterns"
COMPLEX_SUBJ="type=daemon,domain=security,name=auditor,env=prod,tier=backend"
COMPLEX_OBJ="sensitivity=secret,compartment=intel,project=alpha,handling=noforn"
if "$MAC_ABAC_CTL" rule add "allow read $COMPLEX_SUBJ -> $COMPLEX_OBJ" >/dev/null 2>&1; then
    pass "complex patterns accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
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
# Use ctx: before -> for subject, after -> for object
PATTERN_WITH_CTX="type=app,domain=secure,tier=prod,env=test"
if "$MAC_ABAC_CTL" rule add "deny debug $PATTERN_WITH_CTX ctx:uid=0,jail=host,tty=true -> $PATTERN_WITH_CTX ctx:sandboxed=true,jail=any" >/dev/null 2>&1; then
    pass "all context fields + complex patterns accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "all context fields + complex patterns"
fi

run_test
info "Test: Max pattern pairs (8) with all context fields"
# Rule patterns limited to 8 pairs, but context is separate
# Use ctx: before -> for subject, after -> for object
PATTERN_8="k1=v1,k2=v2,k3=v3,k4=v4,k5=v5,k6=v6,k7=v7,k8=v8"
if "$MAC_ABAC_CTL" rule add "deny signal $PATTERN_8 ctx:uid=0,gid=0,jail=host -> $PATTERN_8 ctx:sandboxed=true" >/dev/null 2>&1; then
    pass "8 pattern pairs + all contexts accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "8 pattern pairs + all contexts"
fi

run_test
info "Test: Rule with both subj_context and obj_context"
# Use ctx: before -> for subject, after -> for object
if "$MAC_ABAC_CTL" rule add "deny sched type=a ctx:jail=any -> type=b ctx:jail=host" >/dev/null 2>&1; then
    pass "dual context constraints accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "dual context constraints"
fi

run_test
info "Test: Transition rule with complex newlabel"
COMPLEX_NEWLABEL="type=elevated,domain=system,privileges=admin,audit=required,timestamp=now"
if "$MAC_ABAC_CTL" rule add "transition exec * -> type=setuid => $COMPLEX_NEWLABEL" >/dev/null 2>&1; then
    pass "complex transition rule accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "complex transition rule"
fi

# ===========================================
# Test: Test access with complex labels
# ===========================================
info ""
info "=== Test Access with Complex Labels ==="

"$MAC_ABAC_CTL" rule add "deny read sensitivity=topsecret -> *" >/dev/null 2>&1
"$MAC_ABAC_CTL" rule add "allow read clearance=secret -> sensitivity=secret" >/dev/null 2>&1
"$MAC_ABAC_CTL" rule add "allow read * -> *" >/dev/null 2>&1
"$MAC_ABAC_CTL" default allow >/dev/null 2>&1

run_test
info "Test: Complex label matching - deny"
OUTPUT=$("$MAC_ABAC_CTL" test read "sensitivity=topsecret,compartment=sci" "sensitivity=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
    pass "complex deny match"
else
    fail "complex deny match (got: $OUTPUT)"
fi

run_test
info "Test: Complex label matching - allow"
OUTPUT=$("$MAC_ABAC_CTL" test read "clearance=secret,department=intel" "sensitivity=secret,project=alpha" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
    pass "complex allow match"
else
    fail "complex allow match (got: $OUTPUT)"
fi

"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1

# ===========================================
# Test: Fully loaded rules (max pairs + max length keys/values)
# ===========================================
info ""
info "=== Fully Loaded Rule Tests ==="

# Generate max-length key (63 chars) and value (63 chars)
# ABAC_RULE_KEY_LEN = 64, ABAC_RULE_VALUE_LEN = 64 (63 usable + null)
# Each underscore string below is exactly 62 chars, plus 1-char prefix = 63
MAX_KEY="k______________________________________________________________"
MAX_VAL="v______________________________________________________________"

run_test
info "Test: Single pair with max-length key and value (63 chars each)"
if "$MAC_ABAC_CTL" rule add "allow read ${MAX_KEY}=${MAX_VAL} -> *" >/dev/null 2>&1; then
    pass "max-length key=value accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "max-length key=value"
fi

run_test
info "Test: 8 pairs with max-length keys and values"
# This is the absolute maximum: 8 pairs × (63 + 1 + 63 + 1) = 1024 bytes
# Each key/val is exactly 63 chars: "keyN" (4 chars) + 59 underscores = 63
FULLY_LOADED=""
FULLY_LOADED="${FULLY_LOADED}key1___________________________________________________________=val1___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key2___________________________________________________________=val2___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key3___________________________________________________________=val3___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key4___________________________________________________________=val4___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key5___________________________________________________________=val5___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key6___________________________________________________________=val6___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key7___________________________________________________________=val7___________________________________________________________"
FULLY_LOADED="${FULLY_LOADED},key8___________________________________________________________=val8___________________________________________________________"
if "$MAC_ABAC_CTL" rule add "allow read ${FULLY_LOADED} -> *" >/dev/null 2>&1; then
    pass "8 max-length pairs accepted (fully loaded pattern)"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "8 max-length pairs (fully loaded pattern)"
fi

run_test
info "Test: Fully loaded rule with both subject and object patterns"
if "$MAC_ABAC_CTL" rule add "allow read ${FULLY_LOADED} -> ${FULLY_LOADED}" >/dev/null 2>&1; then
    pass "fully loaded subject AND object patterns accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "fully loaded subject AND object patterns"
fi

run_test
info "Test: Fully loaded rule + all context constraints"
# Use ctx: before -> for subject, after -> for object
if "$MAC_ABAC_CTL" rule add "deny debug ${FULLY_LOADED} ctx:uid=0,gid=0,jail=host,tty=true -> ${FULLY_LOADED} ctx:sandboxed=true,jail=any" >/dev/null 2>&1; then
    pass "fully loaded patterns + all contexts accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "fully loaded patterns + all contexts"
fi

# ===========================================
# Test: Fully loaded transition rules
# ===========================================
info ""
info "=== Fully Loaded Transition Rule Tests ==="

run_test
info "Test: Transition rule with fully loaded newlabel"
if "$MAC_ABAC_CTL" rule add "transition exec * -> type=setuid => ${FULLY_LOADED}" >/dev/null 2>&1; then
    pass "transition with fully loaded newlabel accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "transition with fully loaded newlabel"
fi

run_test
info "Test: Fully loaded transition (all 3 patterns maxed)"
if "$MAC_ABAC_CTL" rule add "transition exec ${FULLY_LOADED} -> ${FULLY_LOADED} => ${FULLY_LOADED}" >/dev/null 2>&1; then
    pass "fully loaded transition rule accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "fully loaded transition rule"
fi

run_test
info "Test: Fully loaded transition + contexts"
if "$MAC_ABAC_CTL" rule add "transition exec ${FULLY_LOADED} -> ${FULLY_LOADED} ctx:uid=0,jail=host => ${FULLY_LOADED}" >/dev/null 2>&1; then
    pass "fully loaded transition + contexts accepted"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    fail "fully loaded transition + contexts"
fi

# ===========================================
# Test: Rules that exceed limits (should fail gracefully)
# ===========================================
info ""
info "=== Oversized Rule Tests (should fail) ==="

# Key too long (64 chars - one over limit)
OVERLONG_KEY="________________________________________________________________"
run_test
info "Test: Key exceeds 63 chars (should fail)"
if "$MAC_ABAC_CTL" rule add "allow read ${OVERLONG_KEY}=value -> *" >/dev/null 2>&1; then
    fail "overlong key should have been rejected"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    pass "overlong key correctly rejected"
fi

# Value too long (64 chars - one over limit)
OVERLONG_VAL="________________________________________________________________"
run_test
info "Test: Value exceeds 63 chars (should fail)"
if "$MAC_ABAC_CTL" rule add "allow read type=${OVERLONG_VAL} -> *" >/dev/null 2>&1; then
    fail "overlong value should have been rejected"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    pass "overlong value correctly rejected"
fi

# Too many pairs (9+)
run_test
info "Test: 9 pairs exceeds limit (should fail)"
NINE_PAIRS="k1=v1,k2=v2,k3=v3,k4=v4,k5=v5,k6=v6,k7=v7,k8=v8,k9=v9"
if "$MAC_ABAC_CTL" rule add "allow read ${NINE_PAIRS} -> *" >/dev/null 2>&1; then
    fail "9 pairs should have been rejected"
    "$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
else
    pass "9 pairs correctly rejected"
fi

# ===========================================
# Test: Verify limits command shows correct values
# ===========================================
info ""
info "=== Limits Display Test ==="

run_test
info "Test: mac_abac_ctl limits shows expected values"
OUTPUT=$("$MAC_ABAC_CTL" limits 2>&1)
if echo "$OUTPUT" | grep -q "Max key=value pairs:  16" && \
   echo "$OUTPUT" | grep -q "Max rules:"; then
    pass "limits command shows expected values"
else
    fail "limits command output unexpected: $OUTPUT"
fi

# ===========================================
# Restore original settings
# ===========================================
info ""
info "Restoring original settings..."
"$MAC_ABAC_CTL" mode "$ORIG_MODE" >/dev/null 2>&1

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
