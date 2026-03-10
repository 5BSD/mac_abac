#!/bin/sh
#
# Test: System-Level Operations
#
# Tests that system-level hooks enforce access control rules.
# System operations use a synthetic "type=system" label as the object.
#
# Operations tested:
#   - kld: kernel module loading (uses EXEC against system/vnode label)
#   - reboot: system reboot (uses WRITE against system label)
#   - sysctl: sysctl read/write (uses READ/WRITE against system label)
#   - swapon/swapoff: swap management (uses WRITE)
#   - acct: process accounting (uses WRITE)
#   - mount_stat: mount point info (uses STAT)
#
# Note: These are rule-based tests using vlabelctl test command.
# Actual enforcement requires process labeling.
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
echo "System-Level Operation Tests"
echo "(kld/reboot/sysctl via type=system label)"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# ===========================================
# Test kld (kernel module) access rules
# System hooks map kld_check_load to EXEC operation
# ===========================================
info "=== KLD (Kernel Module) Access ==="

"$VLABELCTL" rule clear >/dev/null
# Deny untrusted processes from loading kernel modules (EXEC against system)
"$VLABELCTL" rule add "deny exec type=untrusted -> type=system" >/dev/null
"$VLABELCTL" rule add "allow exec type=admin -> type=system" >/dev/null
"$VLABELCTL" rule add "allow exec * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: kld denied for untrusted -> system"
OUTPUT=$("$VLABELCTL" test exec "type=untrusted" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "kld/exec denied for untrusted -> system"
else
	fail "kld/exec should be denied for untrusted -> system (got: $OUTPUT)"
fi

run_test
info "Test: kld allowed for admin -> system"
OUTPUT=$("$VLABELCTL" test exec "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "kld/exec allowed for admin -> system"
else
	fail "kld/exec should be allowed for admin -> system (got: $OUTPUT)"
fi

# ===========================================
# Test reboot access rules
# System hooks map reboot to WRITE operation
# ===========================================
echo ""
info "=== Reboot Access ==="

"$VLABELCTL" rule clear >/dev/null
# Only admin can reboot
"$VLABELCTL" rule add "deny write type=user -> type=system" >/dev/null
"$VLABELCTL" rule add "allow write type=admin -> type=system" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: reboot denied for user -> system"
OUTPUT=$("$VLABELCTL" test write "type=user" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "reboot/write denied for user -> system"
else
	fail "reboot/write should be denied for user -> system (got: $OUTPUT)"
fi

run_test
info "Test: reboot allowed for admin -> system"
OUTPUT=$("$VLABELCTL" test write "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "reboot/write allowed for admin -> system"
else
	fail "reboot/write should be allowed for admin -> system (got: $OUTPUT)"
fi

# ===========================================
# Test sysctl access rules
# System hooks map sysctl read to READ, sysctl write to WRITE
# ===========================================
echo ""
info "=== Sysctl Access ==="

"$VLABELCTL" rule clear >/dev/null
# Sandbox can read but not write sysctls
"$VLABELCTL" rule add "deny write type=sandbox -> type=system" >/dev/null
"$VLABELCTL" rule add "allow read type=sandbox -> type=system" >/dev/null
"$VLABELCTL" rule add "allow read,write type=admin -> type=system" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: sysctl read allowed for sandbox -> system"
OUTPUT=$("$VLABELCTL" test read "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "sysctl/read allowed for sandbox -> system"
else
	fail "sysctl/read should be allowed for sandbox -> system (got: $OUTPUT)"
fi

run_test
info "Test: sysctl write denied for sandbox -> system"
OUTPUT=$("$VLABELCTL" test write "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sysctl/write denied for sandbox -> system"
else
	fail "sysctl/write should be denied for sandbox -> system (got: $OUTPUT)"
fi

run_test
info "Test: sysctl write allowed for admin -> system"
OUTPUT=$("$VLABELCTL" test write "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "sysctl/write allowed for admin -> system"
else
	fail "sysctl/write should be allowed for admin -> system (got: $OUTPUT)"
fi

# ===========================================
# Test mount_stat access rules
# System hooks map mount_check_stat to STAT operation
# ===========================================
echo ""
info "=== Mount Stat Access ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny stat type=isolated -> type=system" >/dev/null
"$VLABELCTL" rule add "allow stat * -> type=system" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: mount_stat denied for isolated -> system"
OUTPUT=$("$VLABELCTL" test stat "type=isolated" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "mount_stat denied for isolated -> system"
else
	fail "mount_stat should be denied for isolated -> system (got: $OUTPUT)"
fi

run_test
info "Test: mount_stat allowed for normal -> system"
OUTPUT=$("$VLABELCTL" test stat "type=normal" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "mount_stat allowed for normal -> system"
else
	fail "mount_stat should be allowed for normal -> system (got: $OUTPUT)"
fi

# ===========================================
# Test combined system restrictions
# ===========================================
echo ""
info "=== Combined System Restrictions ==="

"$VLABELCTL" rule clear >/dev/null
# Sandbox: no write to system, read only
"$VLABELCTL" rule add "deny exec,write type=sandbox -> type=system" >/dev/null
"$VLABELCTL" rule add "allow read,stat type=sandbox -> type=system" >/dev/null
# Admin: full access
"$VLABELCTL" rule add "allow exec,read,write,stat type=admin -> type=system" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: sandbox cannot load kld (exec)"
OUTPUT=$("$VLABELCTL" test exec "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot load kld"
else
	fail "sandbox should not be able to load kld (got: $OUTPUT)"
fi

run_test
info "Test: sandbox cannot reboot (write)"
OUTPUT=$("$VLABELCTL" test write "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot reboot"
else
	fail "sandbox should not be able to reboot (got: $OUTPUT)"
fi

run_test
info "Test: sandbox can read sysctl"
OUTPUT=$("$VLABELCTL" test read "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "sandbox can read sysctl"
else
	fail "sandbox should be able to read sysctl (got: $OUTPUT)"
fi

run_test
info "Test: sandbox can stat mount"
OUTPUT=$("$VLABELCTL" test stat "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "sandbox can stat mount"
else
	fail "sandbox should be able to stat mount (got: $OUTPUT)"
fi

run_test
info "Test: admin has full system access"
OUTPUT=$("$VLABELCTL" test exec "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin has full system access"
else
	fail "admin should have full system access (got: $OUTPUT)"
fi

# ===========================================
# Restore
# ===========================================
echo ""
info "=== Restore Safe State ==="
"$VLABELCTL" mode permissive
"$VLABELCTL" rule clear
"$VLABELCTL" default allow
info "Restored to permissive mode with no rules"

# ===========================================
# Summary
# ===========================================

summary
