#!/bin/sh
#
# Test: Enforcement (exec denial)
#
# Tests that enforcement mode actually blocks labeled binaries.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
#
# Safety:
# - Uses permissive mode first
# - Only blocks /tmp test binaries (not system binaries)
# - Restores permissive mode on exit
# - Has a catch-all allow rule to prevent lockout
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
# Use /root instead of /tmp - tmpfs may not support system extended attributes
# and the kernel needs to read extattrs for label association
TEST_BIN="/root/vlabel_test_$$"

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function - ALWAYS restore safe state
cleanup() {
	# Restore permissive mode
	"$VLABELCTL" mode permissive >/dev/null 2>&1 || true
	# Clear test rules
	"$VLABELCTL" rule clear >/dev/null 2>&1 || true
	# Remove test binary
	rm -f "$TEST_BIN" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Enforcement Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Test binary: $TEST_BIN"
echo ""

# ===========================================
# Setup
# ===========================================
info "=== Setup ==="

# IMPORTANT NOTE ABOUT VNODE LABEL CACHING:
# ==========================================
# The MAC framework caches vnode labels at first kernel access.
# If we create a file, access it (via cp/cat/etc), then add a label,
# the cached label won't be updated until the vnode is reclaimed.
#
# For enforcement testing to work reliably, we need to either:
# 1. Create the labeled binary BEFORE loading the module, OR
# 2. Use a prelabeled test fixture that was set up at deployment time
#
# This test uses method 2 if available, falling back to method 1 with a
# warning if the label isn't being read from extattr.

# Check if pre-labeled test binary exists from deploy-test.sh
# If /root/test_untrusted exists, use that instead
if [ -f "/root/test_untrusted" ]; then
	TEST_BIN_PRELABELED="/root/test_untrusted"
	LABEL=$(getextattr -q system vlabel "$TEST_BIN_PRELABELED" 2>&1)
	if echo "$LABEL" | grep -q "untrusted"; then
		info "Using pre-labeled test binary: $TEST_BIN_PRELABELED"
		TEST_BIN="$TEST_BIN_PRELABELED"
	fi
fi

# If no pre-labeled binary, create one (may not work due to vnode caching)
if [ "$TEST_BIN" = "/root/vlabel_test_$$" ]; then
	warn "Creating test binary on-the-fly (may not work due to vnode label caching)"
	warn "For reliable tests, run deploy-test.sh first to create pre-labeled binaries"

	# Remove any existing test binary
	rm -f "$TEST_BIN"

	# Create the test binary
	dd if=/bin/echo of="$TEST_BIN" bs=64k 2>/dev/null
	chmod +x "$TEST_BIN"

	# Set the label using setextattr with newline format
	setextattr system vlabel "type=untrusted
" "$TEST_BIN"
fi

# Verify the extattr is set
LABEL=$(getextattr -q system vlabel "$TEST_BIN" 2>&1)
info "Test binary extattr: '$LABEL'"

# Verify via vlabelctl
LABEL2=$("$VLABELCTL" label get "$TEST_BIN" 2>&1)
info "Test binary label (vlabelctl): $LABEL2"

# Check filesystem supports extattrs
if [ -z "$LABEL" ]; then
	warn "Failed to set label - filesystem may not support system extattrs"
	warn "Try running test on UFS or ZFS (not tmpfs)"
fi

# Clear any existing rules
"$VLABELCTL" rule clear >/dev/null

# Add rules - ORDER MATTERS (first match wins)
# 1. Deny untrusted
# 2. Allow everything else (safety catch-all)
"$VLABELCTL" rule add "deny exec * -> type=untrusted"
"$VLABELCTL" rule add "allow exec * -> *"

info "Rules loaded:"
"$VLABELCTL" rule list

# ===========================================
# Permissive mode tests
# ===========================================
echo ""
info "=== Permissive Mode Tests ==="

"$VLABELCTL" mode permissive
"$VLABELCTL" audit decisions

run_test
info "Test: Untrusted binary runs in permissive mode"
OUTPUT=$("$TEST_BIN" "permissive test" 2>&1)
if [ "$OUTPUT" = "permissive test" ]; then
	pass "untrusted binary runs in permissive"
else
	fail "untrusted binary runs in permissive (got: $OUTPUT)"
fi

run_test
info "Test: Denial is logged in permissive mode"
STATS=$("$VLABELCTL" stats 2>&1)
if echo "$STATS" | grep -q "Denied:.*[1-9]"; then
	pass "denial logged in stats"
else
	fail "denial logged in stats (got: $STATS)"
fi

# ===========================================
# Enforcing mode tests
# ===========================================
echo ""
info "=== Enforcing Mode Tests ==="

"$VLABELCTL" mode enforcing

run_test
info "Test: Untrusted binary blocked in enforcing mode"
if "$TEST_BIN" "enforcing test" >/dev/null 2>&1; then
	fail "untrusted binary should be blocked"
else
	EXIT_CODE=$?
	if [ "$EXIT_CODE" -eq 126 ]; then
		pass "untrusted binary blocked (exit 126)"
	else
		pass "untrusted binary blocked (exit $EXIT_CODE)"
	fi
fi

run_test
info "Test: Unlabeled binary still runs in enforcing mode"
OUTPUT=$(/bin/echo "system binary" 2>&1)
if [ "$OUTPUT" = "system binary" ]; then
	pass "unlabeled binary runs"
else
	fail "unlabeled binary runs (got: $OUTPUT)"
fi

# ===========================================
# Back to permissive
# ===========================================
echo ""
info "=== Restore Safe State ==="
"$VLABELCTL" mode permissive
info "Mode restored to permissive"

run_test
info "Test: Untrusted binary runs again after permissive"
OUTPUT=$("$TEST_BIN" "back to permissive" 2>&1)
if [ "$OUTPUT" = "back to permissive" ]; then
	pass "untrusted binary runs after restore"
else
	fail "untrusted binary runs after restore (got: $OUTPUT)"
fi

# ===========================================
# Final stats
# ===========================================
echo ""
info "=== Final Statistics ==="
"$VLABELCTL" stats

# ===========================================
# Summary
# ===========================================

summary
