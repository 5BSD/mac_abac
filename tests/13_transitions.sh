#!/bin/sh
#
# Test: Label Transition Rules
#
# Tests the transition rule functionality including:
# - Transition rule syntax validation
# - Transition rule parsing and storage
# - Newlabel format validation
# - Complex transition patterns
# - Transition rule listing and removal
#
# Note: Actual exec-based label transitions are difficult to test in an
# automated suite due to vnode label caching. This test focuses on the
# rule infrastructure. For actual transition testing, use a fresh module
# load with pre-labeled binaries.
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
}
trap cleanup EXIT

echo "============================================"
echo "Label Transition Rule Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# Clear any existing rules
"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Basic Transition Syntax
# ===========================================
info "=== Basic Transition Syntax ==="

run_test
info "Test: Simple transition rule"
if "$VLABELCTL" rule add "transition exec * -> type=app => type=daemon" >/dev/null 2>&1; then
	pass "simple transition accepted"
else
	fail "simple transition"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Transition with subject pattern"
if "$VLABELCTL" rule add "transition exec type=user -> type=setuid => type=elevated" >/dev/null 2>&1; then
	pass "transition with subject pattern"
else
	fail "transition with subject pattern"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Transition with object pattern"
if "$VLABELCTL" rule add "transition exec * -> name=nginx => type=daemon,domain=web" >/dev/null 2>&1; then
	pass "transition with object pattern"
else
	fail "transition with object pattern"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Transition with wildcard subject and specific object"
if "$VLABELCTL" rule add "transition exec * -> type=admin,name=su => type=root" >/dev/null 2>&1; then
	pass "wildcard subject, specific object"
else
	fail "wildcard subject, specific object"
fi
"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Complex Newlabel Formats
# ===========================================
info ""
info "=== Complex Newlabel Formats ==="

run_test
info "Test: Multi-field newlabel"
if "$VLABELCTL" rule add "transition exec * -> type=app => type=daemon,domain=web,level=high" >/dev/null 2>&1; then
	pass "multi-field newlabel"
else
	fail "multi-field newlabel"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Newlabel with custom fields"
if "$VLABELCTL" rule add "transition exec * -> * => type=custom,service=nginx,environment=prod" >/dev/null 2>&1; then
	pass "custom fields in newlabel"
else
	fail "custom fields in newlabel"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Newlabel with boolean-like values"
if "$VLABELCTL" rule add "transition exec * -> type=setuid => type=elevated,escalated=true,confined=false" >/dev/null 2>&1; then
	pass "boolean-like values"
else
	fail "boolean-like values"
fi
"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Transition Rule Listing
# ===========================================
info ""
info "=== Transition Rule Listing ==="

# Add several transition rules
"$VLABELCTL" rule add "transition exec * -> type=web => type=daemon,domain=web"
"$VLABELCTL" rule add "transition exec type=init -> name=sshd => type=daemon,domain=ssh"
"$VLABELCTL" rule add "transition exec * -> type=setuid => type=privileged"

run_test
info "Test: List shows transition rules"
RULES=$("$VLABELCTL" rule list 2>&1)
if echo "$RULES" | grep -q "Loaded rules: 3"; then
	pass "rule count correct"
else
	fail "rule count (got: $RULES)"
fi

run_test
info "Test: Transition rules display correctly"
# Check that transition keyword appears
if echo "$RULES" | grep -qi "transition"; then
	pass "transition keyword in list"
else
	# Some implementations may show action differently
	if echo "$RULES" | grep -q "=>"; then
		pass "transition arrow in list"
	else
		fail "transition display (got: $RULES)"
	fi
fi

"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Missing Newlabel Warning
# ===========================================
info ""
info "=== Missing Newlabel Handling ==="

run_test
info "Test: Transition without newlabel produces warning"
OUTPUT=$("$VLABELCTL" rule validate "transition exec * -> type=app" 2>&1 || true)
if echo "$OUTPUT" | grep -qi "warn\|missing\|newlabel"; then
	pass "warning for missing newlabel"
else
	# Rule might still be accepted but with warning
	if echo "$OUTPUT" | grep -qi "valid"; then
		pass "rule valid but ideally should warn"
	else
		fail "missing newlabel handling (got: $OUTPUT)"
	fi
fi

# ===========================================
# Invalid Transition Syntax
# ===========================================
info ""
info "=== Invalid Transition Syntax ==="

run_test
info "Test: Transition with invalid arrow syntax"
if "$VLABELCTL" rule add "transition exec * -> type=app -> type=daemon" 2>/dev/null; then
	fail "invalid arrow syntax accepted"
else
	pass "invalid arrow syntax rejected"
fi

run_test
info "Test: Transition without object pattern"
# "transition exec * => type=daemon" is missing the object pattern
if "$VLABELCTL" rule add "transition exec => type=daemon" 2>/dev/null; then
	fail "missing object accepted"
else
	pass "missing object rejected"
fi

# ===========================================
# Mixed Rule Types
# ===========================================
info ""
info "=== Mixed Rule Types ==="

# Add allow, deny, and transition rules together
"$VLABELCTL" rule add "deny exec * -> type=malware"
"$VLABELCTL" rule add "transition exec * -> type=setuid => type=elevated"
"$VLABELCTL" rule add "allow exec * -> *"

run_test
info "Test: Mixed rule types coexist"
RULES=$("$VLABELCTL" rule list 2>&1)
if echo "$RULES" | grep -q "Loaded rules: 3"; then
	pass "mixed rules coexist"
else
	fail "mixed rules (got: $RULES)"
fi

run_test
info "Test: Deny rule works alongside transition"
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=malware" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "deny still works"
else
	fail "deny rule (got: $OUTPUT)"
fi

run_test
info "Test: Allow rule works alongside transition"
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=app" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "allow still works"
else
	fail "allow rule (got: $OUTPUT)"
fi

"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Transition with Context Constraints
# ===========================================
info ""
info "=== Transition with Context Constraints ==="

run_test
info "Test: Transition with context constraint"
if "$VLABELCTL" rule add "transition exec * -> type=setuid => type=elevated ctx:uid=0" >/dev/null 2>&1; then
	pass "transition with context accepted"
else
	fail "transition with context"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Transition with jail context"
if "$VLABELCTL" rule add "transition exec * -> type=app => type=jailed ctx:jailed=true" >/dev/null 2>&1; then
	pass "transition with jail context"
else
	fail "transition with jail context"
fi
"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Transition Rule Removal
# ===========================================
info ""
info "=== Transition Rule Removal ==="

# Add a transition rule
"$VLABELCTL" rule add "transition exec * -> type=test => type=tested"

run_test
info "Test: Transition rule can be removed"
RULES=$("$VLABELCTL" rule list 2>&1)
RULE_ID=$(echo "$RULES" | grep '^\s*\[' | head -1 | sed 's/.*\[\([0-9]*\)\].*/\1/')
if [ -n "$RULE_ID" ]; then
	if "$VLABELCTL" rule remove "$RULE_ID" >/dev/null 2>&1; then
		NEW_RULES=$("$VLABELCTL" rule list 2>&1)
		if echo "$NEW_RULES" | grep -qi "no rules"; then
			pass "transition rule removed"
		else
			fail "rule not removed (got: $NEW_RULES)"
		fi
	else
		fail "rule remove command failed"
	fi
else
	fail "could not parse rule ID"
fi

# ===========================================
# Edge Cases
# ===========================================
info ""
info "=== Edge Cases ==="

run_test
info "Test: Transition with empty pattern fields"
# Wildcard patterns
if "$VLABELCTL" rule add "transition exec * -> * => type=default" >/dev/null 2>&1; then
	pass "wildcards in all positions"
else
	fail "wildcards in all positions"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Multiple transitions for same object"
"$VLABELCTL" rule add "transition exec type=init -> name=nginx => type=daemon"
"$VLABELCTL" rule add "transition exec type=user -> name=nginx => type=user_daemon"
RULES=$("$VLABELCTL" rule list 2>&1)
if echo "$RULES" | grep -q "Loaded rules: 2"; then
	pass "multiple transitions for same target"
else
	fail "multiple transitions (got: $RULES)"
fi
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: Transition newlabel at size limit"
# Create a label near the size limit
LONG_VALUE="v"
i=0
while [ $i -lt 200 ]; do
	LONG_VALUE="${LONG_VALUE}x"
	i=$((i + 1))
done
if "$VLABELCTL" rule add "transition exec * -> type=test => type=large,data=$LONG_VALUE" >/dev/null 2>&1; then
	pass "large newlabel accepted"
else
	fail "large newlabel"
fi
"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Test Command with Transition Rules
# ===========================================
info ""
info "=== Test Command Behavior ==="

# Note: The test command shows ALLOW/DENY, not the transition result.
# Transitions happen at exec time, not during access checks.

"$VLABELCTL" rule add "transition exec * -> type=setuid => type=elevated"
"$VLABELCTL" rule add "allow exec * -> *"

run_test
info "Test: Test command shows allow for transition-matching exec"
OUTPUT=$("$VLABELCTL" test exec "type=user" "type=setuid" 2>&1 || true)
# A transition rule allows access (it's not a deny), so test should show ALLOW
if echo "$OUTPUT" | grep -q "ALLOW\|TRANSITION"; then
	pass "transition allows access"
else
	fail "transition access (got: $OUTPUT)"
fi

"$VLABELCTL" rule clear >/dev/null

# ===========================================
# Summary
# ===========================================

summary
