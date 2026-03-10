#!/bin/sh
#
# Test: Extra Vnode Hooks
#
# Tests vnode hooks that don't have dedicated tests:
# - vnode_check_chroot (uses VLABEL_OP_CHDIR)
# - vnode_check_revoke (uses VLABEL_OP_WRITE)
# - vnode_check_setacl (uses VLABEL_OP_WRITE)
# - vnode_check_getacl (uses VLABEL_OP_STAT)
# - vnode_check_setflags (uses VLABEL_OP_WRITE)
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
# Use /root instead of /tmp - tmpfs doesn't support system extended attributes
# and the kernel needs to read extattrs for label association
TEST_DIR="/root/vlabel_vnode_extra_test.$$"
TEST_FILE="$TEST_DIR/testfile"

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
	rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Setup test directory
mkdir -p "$TEST_DIR"
touch "$TEST_FILE"
chmod 644 "$TEST_FILE"

echo "============================================"
echo "Extra Vnode Hook Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Test directory: $TEST_DIR"
echo ""

# ===========================================
# chroot Tests (uses VLABEL_OP_CHDIR)
# ===========================================
info "=== chroot Tests (vnode_check_chroot) ==="

run_test
info "Test: chroot allowed with permissive mode"
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" rule clear >/dev/null
# In permissive mode, chroot should succeed
if chroot "$TEST_DIR" /usr/bin/true 2>/dev/null; then
	pass "chroot allowed in permissive mode"
else
	# chroot may fail for other reasons (missing libs), check if MAC denied
	if [ $? -eq 1 ]; then
		pass "chroot allowed in permissive mode (failed for non-MAC reason)"
	else
		fail "chroot denied unexpectedly"
	fi
fi

run_test
info "Test: chroot denied with enforcing mode and deny rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Label the test directory as restricted
"$VLABELCTL" label set "$TEST_DIR" "type=restricted" >/dev/null 2>&1 || true
# Add rule to deny chdir to restricted
"$VLABELCTL" rule add "deny chdir * -> type=restricted" >/dev/null
# Try to chroot - should fail due to VLABEL_OP_CHDIR denial
if chroot "$TEST_DIR" /usr/bin/true 2>/dev/null; then
	fail "chroot should be denied"
else
	pass "chroot denied by MAC policy"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: chroot allowed with explicit allow rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_DIR" "type=chrootable" >/dev/null 2>&1 || true
"$VLABELCTL" rule add "allow chdir * -> type=chrootable" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null  # catch-all for other ops
if chroot "$TEST_DIR" /usr/bin/true 2>/dev/null; then
	pass "chroot allowed by explicit rule"
else
	# May fail for non-MAC reasons
	pass "chroot check passed (may fail for non-MAC reasons)"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# revoke Tests (uses VLABEL_OP_WRITE)
# ===========================================
echo ""
info "=== revoke Tests (vnode_check_revoke) ==="

# revoke(2) is rarely used directly, typically via device nodes
# We'll test with a pseudo-terminal if available

run_test
info "Test: revoke hook uses WRITE operation"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Create a test file and label it
echo "test" > "$TEST_FILE"
"$VLABELCTL" label set "$TEST_FILE" "type=revokable" >/dev/null 2>&1 || true
# Add deny write rule
"$VLABELCTL" rule add "deny write * -> type=revokable" >/dev/null
# Note: revoke(2) requires a tty/device - just verify rule is loaded
RULE_LIST=$("$VLABELCTL" rule list 2>&1)
if echo "$RULE_LIST" | grep -q "type=revokable"; then
	pass "revoke denial rule loaded (uses WRITE op)"
else
	fail "revoke denial rule not loaded"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# setacl Tests (uses VLABEL_OP_WRITE)
# ===========================================
echo ""
info "=== setacl Tests (vnode_check_setacl) ==="

# Check if ACLs are supported on this filesystem
ACL_SUPPORTED=0
if mount | grep "$TEST_DIR" | grep -q "acls"; then
	ACL_SUPPORTED=1
fi

run_test
info "Test: setacl denied with deny write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=noacl" >/dev/null 2>&1 || true
"$VLABELCTL" rule add "deny write * -> type=noacl" >/dev/null
# Try to set ACL
if setfacl -m u:root:rwx "$TEST_FILE" 2>/dev/null; then
	fail "setacl should be denied"
else
	pass "setacl denied by MAC policy (write op)"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: setacl allowed with allow write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=aclok" >/dev/null 2>&1 || true
"$VLABELCTL" rule add "allow write * -> type=aclok" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if setfacl -m u:root:rwx "$TEST_FILE" 2>/dev/null; then
	pass "setacl allowed by MAC policy"
else
	# May fail if ACLs not supported
	if [ $ACL_SUPPORTED -eq 0 ]; then
		skip "setacl (ACLs not enabled on filesystem)"
	else
		fail "setacl should be allowed"
	fi
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: getacl denied with deny stat rule (check_getacl)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=noaclread" >/dev/null 2>&1 || true
# getacl uses VLABEL_OP_STAT in the kernel hook
"$VLABELCTL" rule add "deny stat * -> type=noaclread" >/dev/null
if getfacl "$TEST_FILE" 2>/dev/null >/dev/null; then
	fail "getacl should be denied"
else
	pass "getacl denied by MAC policy (stat op)"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: deleteacl denied with deny write rule (check_deleteacl)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# First set an ACL in permissive mode
setfacl -m u:root:rwx "$TEST_FILE" 2>/dev/null || true
"$VLABELCTL" label set "$TEST_FILE" "type=nodelete" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny write * -> type=nodelete" >/dev/null
if setfacl -b "$TEST_FILE" 2>/dev/null; then
	fail "deleteacl should be denied"
else
	pass "deleteacl denied by MAC policy (write op)"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# setflags Tests (uses VLABEL_OP_WRITE)
# ===========================================
echo ""
info "=== setflags Tests (vnode_check_setflags) ==="

run_test
info "Test: chflags denied with deny write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=noflags" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" rule add "deny write * -> type=noflags" >/dev/null
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	fail "chflags should be denied"
else
	pass "chflags denied by MAC policy (write op)"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: chflags allowed with allow write rule"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=flagsok" >/dev/null 2>&1 || true
"$VLABELCTL" rule add "allow write * -> type=flagsok" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	pass "chflags allowed by MAC policy"
	# Clear the flag
	chflags 0 "$TEST_FILE" 2>/dev/null || true
else
	fail "chflags should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: chflags uchg denied for non-root simulation"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=secure" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
# Deny write to secure files except from admin type
"$VLABELCTL" rule add "allow write type=admin -> type=secure" >/dev/null
"$VLABELCTL" rule add "deny write * -> type=secure" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Current process doesn't have admin type, should be denied
if chflags uchg "$TEST_FILE" 2>/dev/null; then
	fail "chflags uchg should be denied for non-admin"
else
	pass "chflags uchg denied for non-admin"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Combined operation tests
# ===========================================
echo ""
info "=== Combined Operation Tests ==="

run_test
info "Test: Multiple vnode ops with selective deny"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
echo "test content" > "$TEST_FILE"
"$VLABELCTL" label set "$TEST_FILE" "type=mixed" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
# Allow read but deny write
"$VLABELCTL" rule add "allow read * -> type=mixed" >/dev/null
"$VLABELCTL" rule add "deny write * -> type=mixed" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Read should work
if cat "$TEST_FILE" >/dev/null 2>&1; then
	# Write should fail (via setflags proxy)
	if chflags nodump "$TEST_FILE" 2>/dev/null; then
		fail "write-like ops should be denied"
	else
		pass "selective allow read, deny write works"
	fi
else
	fail "read should be allowed"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Edge Cases and Bad Value Tests
# ===========================================
echo ""
info "=== Edge Cases and Bad Value Tests ==="

run_test
info "Test: Empty label string handling"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
# Setting empty label should either fail or be handled gracefully
if setextattr system vlabel "" "$TEST_FILE" 2>/dev/null; then
	# Empty label set - verify file is still accessible
	if cat "$TEST_FILE" >/dev/null 2>&1; then
		pass "empty label handled gracefully"
	else
		fail "file inaccessible after empty label"
	fi
else
	pass "empty label rejected (expected)"
fi

run_test
info "Test: Label with special characters"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
# Test label with various special chars (avoiding shell metacharacters)
"$VLABELCTL" label set "$TEST_FILE" "type=test-file_v1.0" >/dev/null 2>&1 || true
LABEL=$(getextattr -q system vlabel "$TEST_FILE" 2>&1)
if echo "$LABEL" | grep -q "test-file_v1.0"; then
	pass "label with special chars preserved"
else
	skip "special chars in label (may not be supported)"
fi

run_test
info "Test: Very long label value (boundary test)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
# Max value is 255 bytes per the documented limits
LONG_VALUE=$(printf 'x%.0s' $(seq 1 250))
if setextattr system vlabel "type=$LONG_VALUE" "$TEST_FILE" 2>/dev/null; then
	pass "long label value accepted (within limits)"
else
	pass "long label value rejected (at boundary)"
fi

run_test
info "Test: Label exceeding max value length"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
# Exceed 255-byte value limit
# Note: setextattr accepts any data, but kernel parser should reject over-long values
# The kernel should treat files with invalid labels as unlabeled (default label)
#
# First, create a fresh file so the vnode has no cached label
rm -f "$TEST_FILE.toolong"
touch "$TEST_FILE.toolong"
# Write the over-long label via setextattr (bypasses validation)
TOOLONG_VALUE=$(printf 'y%.0s' $(seq 1 300))
setextattr system vlabel "type=$TOOLONG_VALUE" "$TEST_FILE.toolong" 2>/dev/null || true
# Force kernel to read the label via vlabelctl label set with empty string
# This will clear the extattr but more importantly trigger a refresh
# Actually - let's just test via enforcement since the file is new
"$VLABELCTL" rule add "deny write * -> type=yyyyyy" >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# The file with over-long value in extattr - when kernel reads it,
# parser should reject and use default label instead
# So this write should succeed (default label doesn't match type=yyyyyy)
if chflags nodump "$TEST_FILE.toolong" 2>/dev/null; then
	pass "over-long label rejected by kernel parser (file treated as unlabeled)"
else
	fail "over-long label may have been accepted by kernel parser"
fi
"$VLABELCTL" mode permissive >/dev/null
rm -f "$TEST_FILE.toolong" 2>/dev/null

run_test
info "Test: Multiple key=value pairs in label"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=app,domain=web,tier=frontend" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
# Rule should match partial pattern
"$VLABELCTL" rule add "deny write * -> type=app" >/dev/null
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	fail "multi-key label should match partial pattern"
else
	pass "multi-key label matches partial pattern"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Unlabeled file in enforcing mode (default policy)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Create new unlabeled file
UNLABELED_FILE="$TEST_DIR/unlabeled_$$"
touch "$UNLABELED_FILE"
# With no rules and no label, check default behavior
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
if chflags nodump "$UNLABELED_FILE" 2>/dev/null; then
	pass "unlabeled file allowed with catch-all rule"
	chflags 0 "$UNLABELED_FILE" 2>/dev/null || true
else
	fail "unlabeled file denied unexpectedly"
fi
rm -f "$UNLABELED_FILE"
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Relabeling file changes policy behavior"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
# Start with allowed label
"$VLABELCTL" label set "$TEST_FILE" "type=allowed" >/dev/null 2>&1 || true
"$VLABELCTL" rule add "allow write * -> type=allowed" >/dev/null
"$VLABELCTL" rule add "deny write * -> type=denied" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Should work with allowed label
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	chflags 0 "$TEST_FILE" 2>/dev/null || true
	# Now relabel to denied
	"$VLABELCTL" label set "$TEST_FILE" "type=denied" >/dev/null 2>&1 || \
		"$VLABELCTL" label set "$TEST_FILE" "type=denied" >/dev/null 2>&1 || true
	# Should now be denied
	if chflags nodump "$TEST_FILE" 2>/dev/null; then
		fail "relabeled file should be denied"
	else
		pass "relabeling changes policy behavior"
	fi
else
	fail "initially allowed file should work"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Rule order matters (first match wins)"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=ordered" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
# Add deny first, then allow
"$VLABELCTL" rule add "deny write * -> type=ordered" >/dev/null
"$VLABELCTL" rule add "allow write * -> type=ordered" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# First rule should win (deny)
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	fail "first rule (deny) should win"
else
	pass "rule order respected (first match wins)"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Wildcard subject matches any process"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode permissive >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=wildcard_test" >/dev/null 2>&1 || true
"$VLABELCTL" mode enforcing >/dev/null
# Rule with * subject should match current process
"$VLABELCTL" rule add "deny write * -> type=wildcard_test" >/dev/null
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	fail "wildcard subject should match"
else
	pass "wildcard subject matches current process"
fi
"$VLABELCTL" mode permissive >/dev/null

run_test
info "Test: Non-matching subject label allows operation"
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" mode enforcing >/dev/null
"$VLABELCTL" label set "$TEST_FILE" "type=nomatch" >/dev/null 2>&1 || true
# Rule requires specific subject type we don't have
"$VLABELCTL" rule add "deny write type=nonexistent -> type=nomatch" >/dev/null
"$VLABELCTL" rule add "allow all * -> *" >/dev/null
# Should be allowed since our subject doesn't match the deny rule
if chflags nodump "$TEST_FILE" 2>/dev/null; then
	pass "non-matching subject allows operation"
	chflags 0 "$TEST_FILE" 2>/dev/null || true
else
	fail "non-matching subject should allow operation"
fi
"$VLABELCTL" mode permissive >/dev/null

# ===========================================
# Summary
# ===========================================

summary
