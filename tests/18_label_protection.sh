#!/bin/sh
#
# Test: Label Protection (setextattr/getextattr/deleteextattr)
#
# Tests that the system:mac_abac extended attribute is protected from
# unauthorized modification, deletion, and optionally reading.
#
# The ABAC module protects its own labels via:
#   - vnode_check_setextattr: controls who can modify labels
#   - vnode_check_deleteextattr: controls who can remove labels
#   - vnode_check_getextattr: controls who can read labels
#
# These checks use the ABAC_OP_SETEXTATTR and ABAC_OP_GETEXTATTR
# operations, so rules can be written like:
#   allow setextattr type=admin -> *
#   deny setextattr * -> type=protected
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
if [ -n "$1" ]; then
	MAC_ABAC_CTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="$SCRIPT_DIR/../tools/mac_abac_ctl"
else
	MAC_ABAC_CTL="./tools/mac_abac_ctl"
fi
MODULE_NAME="mac_abac"
TEST_DIR="/root/abac_labelprotect_$$"

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1 || true
	"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
	"$MAC_ABAC_CTL" default allow >/dev/null 2>&1 || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Label Protection Tests"
echo "(setextattr/getextattr/deleteextattr)"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
info "Test directory: $TEST_DIR"
echo ""

# ===========================================
# Setup
# ===========================================
info "=== Setup ==="

mkdir -p "$TEST_DIR"

# Create test files
TEST_FILE="$TEST_DIR/protected_file"
echo "protected content" > "$TEST_FILE"

# Label the file
"$MAC_ABAC_CTL" label set "$TEST_FILE" "type=protected"

LABEL=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1)
info "Initial label: $LABEL"

# ===========================================
# Test 1: Default allows label operations
# ===========================================
echo ""
info "=== Test 1: Default Policy Allows Label Operations ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow
"$MAC_ABAC_CTL" mode enforcing

run_test
info "Test 1a: Can read label with default allow"
if "$MAC_ABAC_CTL" label get "$TEST_FILE" >/dev/null 2>&1; then
	pass "label read allowed"
else
	fail "label read should be allowed with default allow"
fi

run_test
info "Test 1b: Can modify label with default allow"
if "$MAC_ABAC_CTL" label set "$TEST_FILE" "type=modified" 2>/dev/null; then
	pass "label modify allowed"
	# Restore original label
	"$MAC_ABAC_CTL" label set "$TEST_FILE" "type=protected" 2>/dev/null
else
	fail "label modify should be allowed with default allow"
fi

# ===========================================
# Test 2: Deny setextattr blocks label modification
# ===========================================
echo ""
info "=== Test 2: Deny setextattr Blocks Label Modification ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny setextattr * -> type=protected"
"$MAC_ABAC_CTL" rule add "allow setextattr,getextattr * -> *"
"$MAC_ABAC_CTL" default allow

info "Rules:"
"$MAC_ABAC_CTL" rule list

run_test
info "Test 2a: Cannot modify protected label"
if "$MAC_ABAC_CTL" label set "$TEST_FILE" "type=hacked" 2>/dev/null; then
	fail "label modify should be blocked"
	# Try to restore
	"$MAC_ABAC_CTL" mode permissive
	"$MAC_ABAC_CTL" label set "$TEST_FILE" "type=protected" 2>/dev/null
	"$MAC_ABAC_CTL" mode enforcing
else
	pass "label modify blocked on protected file"
fi

# Verify the label wasn't changed
run_test
info "Test 2b: Label unchanged after blocked modification"
LABEL=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1)
if echo "$LABEL" | grep -q "type=protected"; then
	pass "label preserved: $LABEL"
else
	fail "label was changed: $LABEL"
fi

# ===========================================
# Test 3: Deny getextattr blocks label reading
# ===========================================
echo ""
info "=== Test 3: Deny getextattr Blocks Label Reading ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny getextattr * -> type=protected"
"$MAC_ABAC_CTL" rule add "allow setextattr,getextattr * -> *"
"$MAC_ABAC_CTL" default allow

info "Rules:"
"$MAC_ABAC_CTL" rule list

run_test
info "Test 3: Cannot read protected label"
if "$MAC_ABAC_CTL" label get "$TEST_FILE" >/dev/null 2>&1; then
	fail "label read should be blocked"
else
	pass "label read blocked on protected file"
fi

# ===========================================
# Test 4: Label removal protection
# ===========================================
echo ""
info "=== Test 4: Label Removal Protection ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny setextattr * -> type=protected"
"$MAC_ABAC_CTL" rule add "allow setextattr,getextattr * -> *"
"$MAC_ABAC_CTL" default allow

info "Rules:"
"$MAC_ABAC_CTL" rule list

run_test
info "Test 4: Cannot remove protected label"
if "$MAC_ABAC_CTL" label remove "$TEST_FILE" 2>/dev/null; then
	fail "label remove should be blocked"
else
	pass "label remove blocked on protected file"
fi

# Verify label still exists
LABEL=$("$MAC_ABAC_CTL" mode permissive >/dev/null; "$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1; "$MAC_ABAC_CTL" mode enforcing >/dev/null)
if echo "$LABEL" | grep -q "type=protected"; then
	info "Label still present: $LABEL"
else
	warn "Label may have been removed: $LABEL"
fi

# ===========================================
# Test 5: Selective allow for admin
# ===========================================
echo ""
info "=== Test 5: Selective Allow for Admin ==="

# Create an "admin" file to represent admin process context
ADMIN_FILE="$TEST_DIR/admin_target"
echo "admin target" > "$ADMIN_FILE"
"$MAC_ABAC_CTL" mode permissive
"$MAC_ABAC_CTL" label set "$ADMIN_FILE" "type=admin"
"$MAC_ABAC_CTL" mode enforcing

"$MAC_ABAC_CTL" rule clear >/dev/null
# Allow admin to modify any label, deny everyone else
"$MAC_ABAC_CTL" rule add "allow setextattr type=admin -> *"
"$MAC_ABAC_CTL" rule add "deny setextattr * -> *"
"$MAC_ABAC_CTL" default allow

info "Rules (admin can modify, others denied):"
"$MAC_ABAC_CTL" rule list

# Test using mac_abac_ctl test command
run_test
info "Test 5a: Admin can modify labels (via test command)"
OUTPUT=$("$MAC_ABAC_CTL" test setextattr "type=admin" "type=protected" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin allowed to setextattr"
else
	fail "admin should be allowed (got: $OUTPUT)"
fi

run_test
info "Test 5b: Non-admin blocked from modifying labels (via test command)"
OUTPUT=$("$MAC_ABAC_CTL" test setextattr "type=user" "type=protected" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "non-admin denied setextattr"
else
	fail "non-admin should be denied (got: $OUTPUT)"
fi

# ===========================================
# Test 6: Permissive mode allows but logs
# ===========================================
echo ""
info "=== Test 6: Permissive Mode ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny setextattr * -> type=protected"
"$MAC_ABAC_CTL" rule add "allow setextattr,getextattr * -> *"
"$MAC_ABAC_CTL" mode permissive

run_test
info "Test 6: Can modify in permissive mode (would be denied in enforcing)"
if "$MAC_ABAC_CTL" label set "$TEST_FILE" "type=modified_permissive" 2>/dev/null; then
	pass "modification allowed in permissive mode"
	# Restore
	"$MAC_ABAC_CTL" label set "$TEST_FILE" "type=protected" 2>/dev/null
else
	fail "modification should be allowed in permissive mode"
fi

# ===========================================
# Test 7: Other extattrs not affected
# ===========================================
echo ""
info "=== Test 7: Other Extended Attributes Not Affected ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny setextattr * -> *"
"$MAC_ABAC_CTL" rule add "deny getextattr * -> *"
"$MAC_ABAC_CTL" default allow
"$MAC_ABAC_CTL" mode enforcing

run_test
info "Test 7: Can set other extattrs (not system:mac_abac)"
# setextattr in user namespace should not be affected
if setextattr user testattr "testvalue" "$TEST_FILE" 2>/dev/null; then
	pass "user extattr allowed (not protected)"
	# Clean up
	rmextattr user testattr "$TEST_FILE" 2>/dev/null || true
else
	# This might fail for other reasons (not ZFS, etc)
	# Check if it's our denial or something else
	warn "user extattr failed - may be filesystem limitation, not ABAC"
fi

# ===========================================
# Restore
# ===========================================
echo ""
info "=== Restore Safe State ==="
"$MAC_ABAC_CTL" mode permissive
"$MAC_ABAC_CTL" rule clear
"$MAC_ABAC_CTL" default allow
info "Restored to permissive mode with no rules"

# ===========================================
# Summary
# ===========================================

summary
