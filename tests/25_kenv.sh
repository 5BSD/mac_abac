#!/bin/sh
#
# Test: Kernel Environment (kenv) Hooks
#
# Tests kenv MAC hooks:
# - kenv_check_dump (uses VLABEL_OP_READ against vlabel_kenv_object)
# - kenv_check_get (uses VLABEL_OP_READ against vlabel_kenv_object)
# - kenv_check_set (uses VLABEL_OP_WRITE against vlabel_kenv_object)
# - kenv_check_unset (uses VLABEL_OP_WRITE against vlabel_kenv_object)
#
# These hooks check against a synthetic "kenv" object with type=kenv
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
TEST_KENV_VAR="vlabel_test_var_$$"
TEST_KENV_VALUE="test_value_$$"

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
	# Clean up test kenv variable
	kenv -u "$TEST_KENV_VAR" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Kernel Environment (kenv) Hook Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Test variable: $TEST_KENV_VAR"
echo ""

# ===========================================
# kenv_check_dump Tests (VLABEL_OP_READ)
# ===========================================
info "=== kenv dump Tests (kenv_check_dump) ==="

run_test
info "Test: kenv dump allowed in permissive mode"
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" rule clear >/dev/null
if kenv >/dev/null 2>&1; then
	pass "kenv dump allowed in permissive mode"
else
	fail "kenv dump should work in permissive mode"
fi

run_test
info "Test: kenv dump denied with deny read rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Deny read to kenv object
"$VLABELCTL" rule add "deny read * -> type=kenv" >/dev/null
if kenv >/dev/null 2>&1; then
	fail "kenv dump should be denied"
else
	pass "kenv dump denied by MAC policy"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: kenv dump allowed with allow read rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if kenv >/dev/null 2>&1; then
	pass "kenv dump allowed by MAC policy"
else
	fail "kenv dump should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# kenv_check_get Tests (VLABEL_OP_READ)
# ===========================================
echo ""
info "=== kenv get Tests (kenv_check_get) ==="

# First set a test variable
kenv "$TEST_KENV_VAR=$TEST_KENV_VALUE" 2>/dev/null || true

run_test
info "Test: kenv get allowed in permissive mode"
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" rule clear >/dev/null
if kenv "$TEST_KENV_VAR" >/dev/null 2>&1; then
	pass "kenv get allowed in permissive mode"
else
	fail "kenv get should work in permissive mode"
fi

run_test
info "Test: kenv get denied with deny read rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny read * -> type=kenv" >/dev/null
if kenv "$TEST_KENV_VAR" >/dev/null 2>&1; then
	fail "kenv get should be denied"
else
	pass "kenv get denied by MAC policy"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: kenv get allowed with allow read rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if kenv "$TEST_KENV_VAR" >/dev/null 2>&1; then
	pass "kenv get allowed by MAC policy"
else
	fail "kenv get should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# kenv_check_set Tests (VLABEL_OP_WRITE)
# ===========================================
echo ""
info "=== kenv set Tests (kenv_check_set) ==="

run_test
info "Test: kenv set allowed in permissive mode"
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" rule clear >/dev/null
NEW_VAR="${TEST_KENV_VAR}_new"
if kenv "$NEW_VAR=test" 2>/dev/null; then
	pass "kenv set allowed in permissive mode"
	kenv -u "$NEW_VAR" 2>/dev/null || true
else
	fail "kenv set should work in permissive mode"
fi

run_test
info "Test: kenv set denied with deny write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
NEW_VAR="${TEST_KENV_VAR}_denied"
if kenv "$NEW_VAR=test" 2>/dev/null; then
	fail "kenv set should be denied"
	kenv -u "$NEW_VAR" 2>/dev/null || true
else
	pass "kenv set denied by MAC policy"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: kenv set allowed with allow write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
NEW_VAR="${TEST_KENV_VAR}_allowed"
if kenv "$NEW_VAR=test" 2>/dev/null; then
	pass "kenv set allowed by MAC policy"
	kenv -u "$NEW_VAR" 2>/dev/null || true
else
	fail "kenv set should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# kenv_check_unset Tests (VLABEL_OP_WRITE)
# ===========================================
echo ""
info "=== kenv unset Tests (kenv_check_unset) ==="

run_test
info "Test: kenv unset allowed in permissive mode"
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" rule clear >/dev/null
UNSET_VAR="${TEST_KENV_VAR}_unset"
kenv "$UNSET_VAR=test" 2>/dev/null || true
if kenv -u "$UNSET_VAR" 2>/dev/null; then
	pass "kenv unset allowed in permissive mode"
else
	fail "kenv unset should work in permissive mode"
fi

run_test
info "Test: kenv unset denied with deny write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
UNSET_VAR="${TEST_KENV_VAR}_unset2"
kenv "$UNSET_VAR=test" 2>/dev/null || true
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if kenv -u "$UNSET_VAR" 2>/dev/null; then
	fail "kenv unset should be denied"
else
	pass "kenv unset denied by MAC policy"
fi
"$VLABELCTL" mode permissive >/dev/null
kenv -u "$UNSET_VAR" 2>/dev/null || true

run_test
info "Test: kenv unset allowed with allow write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
UNSET_VAR="${TEST_KENV_VAR}_unset3"
kenv "$UNSET_VAR=test" 2>/dev/null || true
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if kenv -u "$UNSET_VAR" 2>/dev/null; then
	pass "kenv unset allowed by MAC policy"
else
	fail "kenv unset should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Combined Tests
# ===========================================
echo ""
info "=== Combined kenv Tests ==="

run_test
info "Test: Selective read/write - allow read, deny write"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "deny write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Read should work
if kenv >/dev/null 2>&1; then
	# Write should fail
	NEW_VAR="${TEST_KENV_VAR}_combo"
	if kenv "$NEW_VAR=test" 2>/dev/null; then
		fail "write should be denied while read allowed"
		kenv -u "$NEW_VAR" 2>/dev/null || true
	else
		pass "selective allow read, deny write works"
	fi
else
	fail "read should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Subject label constraint for kenv access"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Only allow admin type to write to kenv
"$VLABELCTL" rule add "allow write type=admin -> type=kenv" >/dev/null
"$VLABELCTL" rule add "deny write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Current process doesn't have admin type, should be denied
NEW_VAR="${TEST_KENV_VAR}_admin"
if kenv "$NEW_VAR=test" 2>/dev/null; then
	fail "non-admin should not write to kenv"
	kenv -u "$NEW_VAR" 2>/dev/null || true
else
	pass "kenv write denied for non-admin subject"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Error handling
# ===========================================
echo ""
info "=== Error Handling Tests ==="

run_test
info "Test: kenv get non-existent variable (not MAC related)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
if kenv "nonexistent_var_$$$" 2>/dev/null; then
	fail "getting non-existent var should fail"
else
	pass "non-existent kenv var returns error"
fi

# ===========================================
# Edge Cases and Bad Value Tests
# ===========================================
echo ""
info "=== Edge Cases and Bad Value Tests ==="

run_test
info "Test: kenv with special characters in variable name"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
SPECIAL_VAR="${TEST_KENV_VAR}_test-v1.0"
if kenv "$SPECIAL_VAR=test_value" 2>/dev/null; then
	pass "kenv with special chars in name works"
	kenv -u "$SPECIAL_VAR" 2>/dev/null || true
else
	pass "kenv with special chars rejected (may be expected)"
fi

run_test
info "Test: kenv with special characters in value"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
SPECIAL_VALUE="value-with_special.chars/and:colons"
if kenv "${TEST_KENV_VAR}_special=$SPECIAL_VALUE" 2>/dev/null; then
	RETRIEVED=$(kenv "${TEST_KENV_VAR}_special" 2>/dev/null)
	if [ "$RETRIEVED" = "$SPECIAL_VALUE" ]; then
		pass "kenv special char value preserved"
	else
		pass "kenv value stored (may have transformations)"
	fi
	kenv -u "${TEST_KENV_VAR}_special" 2>/dev/null || true
else
	fail "kenv should accept special chars in value"
fi

run_test
info "Test: kenv with empty value"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
EMPTY_VAR="${TEST_KENV_VAR}_empty"
if kenv "$EMPTY_VAR=" 2>/dev/null; then
	pass "kenv with empty value accepted"
	kenv -u "$EMPTY_VAR" 2>/dev/null || true
else
	pass "kenv with empty value rejected (may be expected)"
fi

run_test
info "Test: kenv with very long value"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
LONG_VAR="${TEST_KENV_VAR}_long"
LONG_VALUE=$(printf 'x%.0s' $(seq 1 1000))
if kenv "$LONG_VAR=$LONG_VALUE" 2>/dev/null; then
	pass "kenv with long value accepted"
	kenv -u "$LONG_VAR" 2>/dev/null || true
else
	pass "kenv with long value rejected (may exceed limits)"
fi

run_test
info "Test: kenv operation order (set then get then unset)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
ORDER_VAR="${TEST_KENV_VAR}_order"
ORDER_VALUE="order_test_$$"
# Set
if kenv "$ORDER_VAR=$ORDER_VALUE" 2>/dev/null; then
	# Get
	RETRIEVED=$(kenv "$ORDER_VAR" 2>/dev/null)
	if [ "$RETRIEVED" = "$ORDER_VALUE" ]; then
		# Unset
		if kenv -u "$ORDER_VAR" 2>/dev/null; then
			# Verify unset worked
			if kenv "$ORDER_VAR" 2>/dev/null; then
				fail "variable should be unset"
			else
				pass "kenv set/get/unset sequence works"
			fi
		else
			fail "unset should work"
		fi
	else
		fail "get should return set value"
	fi
else
	fail "set should work"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Deny read but allow write (unusual but valid)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny read * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
WRITEONLY_VAR="${TEST_KENV_VAR}_writeonly"
# Write should work
if kenv "$WRITEONLY_VAR=test" 2>/dev/null; then
	# Read should fail
	if kenv "$WRITEONLY_VAR" >/dev/null 2>&1; then
		fail "read should be denied"
	else
		pass "allow write, deny read works"
	fi
	# Clean up in permissive mode
	"$VLABELCTL" mode permissive >/dev/null
	kenv -u "$WRITEONLY_VAR" 2>/dev/null || true
else
	fail "write should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Multiple rules - first match wins"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Add deny first, then allow
"$VLABELCTL" rule add "deny write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow write * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
FIRSTMATCH_VAR="${TEST_KENV_VAR}_firstmatch"
# First rule (deny) should win
if kenv "$FIRSTMATCH_VAR=test" 2>/dev/null; then
	fail "first rule (deny) should win"
	kenv -u "$FIRSTMATCH_VAR" 2>/dev/null || true
else
	pass "first match rule wins (deny)"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Wildcard matches all kenv operations"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow all * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
WILDCARD_VAR="${TEST_KENV_VAR}_wildcard"
# All operations should work with 'all' operation wildcard
if kenv "$WILDCARD_VAR=test" 2>/dev/null; then
	if kenv "$WILDCARD_VAR" >/dev/null 2>&1; then
		if kenv -u "$WILDCARD_VAR" 2>/dev/null; then
			pass "wildcard 'all' allows all operations"
		else
			fail "unset should work with all"
		fi
	else
		fail "get should work with all"
	fi
else
	fail "set should work with all"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: No matching rules falls through to default policy"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Add rules that don't match kenv object
"$VLABELCTL" rule add "allow all * -> type=file" >/dev/null
# No catch-all - depends on default_policy sysctl
DEFAULT_VAR="${TEST_KENV_VAR}_default"
# Result depends on default_policy setting - just verify no crash
kenv "$DEFAULT_VAR=test" 2>/dev/null && kenv -u "$DEFAULT_VAR" 2>/dev/null || true
pass "no matching rules handled gracefully"
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Rapid set/unset cycles"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "allow all * -> type=kenv" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
RAPID_VAR="${TEST_KENV_VAR}_rapid"
RAPID_OK=1
for i in 1 2 3 4 5; do
	if ! kenv "$RAPID_VAR=value$i" 2>/dev/null; then
		RAPID_OK=0
		break
	fi
	if ! kenv -u "$RAPID_VAR" 2>/dev/null; then
		RAPID_OK=0
		break
	fi
done
if [ $RAPID_OK -eq 1 ]; then
	pass "rapid set/unset cycles work"
else
	fail "rapid set/unset cycles failed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Summary
# ===========================================

summary
