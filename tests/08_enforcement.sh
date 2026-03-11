#!/bin/sh
#
# Test: Enforcement (exec denial)
#
# Tests that enforcement mode actually blocks labeled binaries.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must be built
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

# Configuration - check installed locations first, then local build
if [ -n "$1" ]; then
	MAC_ABAC_CTL="$1"
elif [ -x "/usr/local/sbin/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="/usr/local/sbin/mac_abac_ctl"
elif [ -x "/usr/local/bin/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="/usr/local/bin/mac_abac_ctl"
elif [ -x "$SCRIPT_DIR/../tools/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="$SCRIPT_DIR/../tools/mac_abac_ctl"
else
	MAC_ABAC_CTL="mac_abac_ctl"
fi
MODULE_NAME="mac_abac"
# Use /root instead of /tmp - tmpfs may not support system extended attributes
# and the kernel needs to read extattrs for label association
TEST_BIN="/root/abac_test_$$"
USE_PRELABELED=0

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function - ALWAYS restore safe state
cleanup() {
	# Restore permissive mode
	"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1 || true
	# Clear test rules
	"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
	# Remove test binary ONLY if we created it (not the pre-labeled one)
	if [ "$USE_PRELABELED" -eq 0 ]; then
		rm -f "$TEST_BIN" 2>/dev/null || true
	fi
}
trap cleanup EXIT

echo "============================================"
echo "Enforcement Tests"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
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
# If /root/test_untrusted exists with a valid label, use that instead
if [ -f "/root/test_untrusted" ]; then
	LABEL=$(getextattr -q system mac_abac "/root/test_untrusted" 2>&1 || true)
	if echo "$LABEL" | grep -q "untrusted"; then
		info "Using pre-labeled test binary: /root/test_untrusted"
		TEST_BIN="/root/test_untrusted"
		USE_PRELABELED=1
	else
		info "Pre-labeled binary exists but has no label, will create new test binary"
	fi
fi

# If no pre-labeled binary, create one using mac_abac_ctl label set
# (which now supports live relabeling via ABAC_SYS_REFRESH)
if [ "$USE_PRELABELED" -eq 0 ]; then
	info "Creating test binary on-the-fly with live relabeling"

	# Remove any existing test binary
	rm -f "$TEST_BIN"

	# Create the test binary
	dd if=/bin/echo of="$TEST_BIN" bs=64k 2>/dev/null
	chmod +x "$TEST_BIN"

	# Set the label using mac_abac_ctl (writes extattr + refreshes cached label)
	"$MAC_ABAC_CTL" label set "$TEST_BIN" "type=untrusted"
fi

# Verify the extattr is set
LABEL=$(getextattr -q system mac_abac "$TEST_BIN" 2>&1)
info "Test binary extattr: '$LABEL'"

# Verify via mac_abac_ctl
LABEL2=$("$MAC_ABAC_CTL" label get "$TEST_BIN" 2>&1)
info "Test binary label (mac_abac_ctl): $LABEL2"

# Check filesystem supports extattrs
if [ -z "$LABEL" ]; then
	warn "Failed to set label - filesystem may not support system extattrs"
	warn "Try running test on UFS or ZFS (not tmpfs)"
fi

# Verify the label is set by checking stats
# mac_abac_ctl label set uses ABAC_SYS_REFRESH to update the cached label,
# so live relabeling should work without needing pre-labeled binaries.
STATS=$("$MAC_ABAC_CTL" stats 2>&1)
LABELS_READ=$(echo "$STATS" | grep "Labels read:" | awk '{print $3}')
info "Labels read from extattr: $LABELS_READ"

# Clear any existing rules
"$MAC_ABAC_CTL" rule clear >/dev/null

# Add rules - ORDER MATTERS (first match wins)
# 1. Deny untrusted
# 2. Allow everything else (safety catch-all)
"$MAC_ABAC_CTL" rule add "deny exec * -> type=untrusted"
"$MAC_ABAC_CTL" rule add "allow exec * -> *"

info "Rules loaded:"
"$MAC_ABAC_CTL" rule list

# ===========================================
# Permissive mode tests
# ===========================================
echo ""
info "=== Permissive Mode Tests ==="

"$MAC_ABAC_CTL" mode permissive

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
STATS=$("$MAC_ABAC_CTL" stats 2>&1)
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

"$MAC_ABAC_CTL" mode enforcing

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
"$MAC_ABAC_CTL" mode permissive
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
"$MAC_ABAC_CTL" stats

# ===========================================
# Summary
# ===========================================

summary
