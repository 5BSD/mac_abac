#!/bin/sh
#
# Test: POSIX Shared Memory Operations
#
# Tests that POSIX shm hooks enforce access control rules.
#
# POSIX shm labels are inherited from the creating process credential.
# Like pipes, shm objects cannot be labeled via extattr - they are
# in-memory objects. Rules can control:
#   - open: shm_open()
#   - read: reading from shm
#   - write: writing to shm
#   - mmap: mapping shm into memory
#   - stat: fstat on shm
#   - unlink: shm_unlink()
#
# Since we can't directly label shm objects, we test rule parsing and
# evaluation via mac_abac_ctl test command.
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration - find mac_abac_ctl
MAC_ABAC_CTL="${1:-$(find_mac_abac_ctl)}"
MODULE_NAME="mac_abac"

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
}
trap cleanup EXIT

echo "============================================"
echo "POSIX Shared Memory Tests"
echo "(open/read/write/mmap/stat/unlink)"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
echo ""

# ===========================================
# Setup - Test rule parsing
# ===========================================
info "=== Rule Parsing ==="

"$MAC_ABAC_CTL" rule clear >/dev/null

run_test
info "Test: open operation for shm"
if "$MAC_ABAC_CTL" rule add "deny open type=untrusted -> type=secret" >/dev/null 2>&1; then
	pass "open operation accepted"
else
	fail "open operation should be accepted"
fi

run_test
info "Test: mmap operation for shm"
if "$MAC_ABAC_CTL" rule add "deny mmap type=sandbox -> type=sensitive" >/dev/null 2>&1; then
	pass "mmap operation accepted"
else
	fail "mmap operation should be accepted"
fi

run_test
info "Test: unlink operation for shm"
if "$MAC_ABAC_CTL" rule add "deny unlink type=user -> type=system" >/dev/null 2>&1; then
	pass "unlink operation accepted"
else
	fail "unlink operation should be accepted"
fi

# ===========================================
# Test shm operations via mac_abac_ctl test
# ===========================================
echo ""
info "=== Test Command Verification ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny open type=untrusted -> type=secret" >/dev/null
"$MAC_ABAC_CTL" rule add "allow open * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: open denied for untrusted -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test open "type=untrusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "open denied for untrusted -> secret"
else
	fail "open should be denied for untrusted -> secret (got: $OUTPUT)"
fi

run_test
info "Test: open allowed for trusted -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test open "type=trusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "open allowed for trusted -> secret"
else
	fail "open should be allowed for trusted -> secret (got: $OUTPUT)"
fi

# ===========================================
# Test mmap restrictions
# ===========================================
echo ""
info "=== MMAP Restrictions ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny mmap type=sandbox -> type=sensitive" >/dev/null
"$MAC_ABAC_CTL" rule add "allow mmap * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: mmap denied for sandbox -> sensitive"
OUTPUT=$("$MAC_ABAC_CTL" test mmap "type=sandbox" "type=sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "mmap denied for sandbox -> sensitive"
else
	fail "mmap should be denied for sandbox -> sensitive (got: $OUTPUT)"
fi

run_test
info "Test: mmap allowed for trusted -> sensitive"
OUTPUT=$("$MAC_ABAC_CTL" test mmap "type=trusted" "type=sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "mmap allowed for trusted -> sensitive"
else
	fail "mmap should be allowed for trusted -> sensitive (got: $OUTPUT)"
fi

# ===========================================
# Test combined read/write rules
# ===========================================
echo ""
info "=== Combined Read/Write Rules ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
# Isolated process: no read or write to shm with secret label
"$MAC_ABAC_CTL" rule add "deny read,write type=isolated -> type=secret" >/dev/null
# Allow all other shm ops
"$MAC_ABAC_CTL" rule add "allow read,write,open,mmap,stat * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: isolated cannot read secret shm"
OUTPUT=$("$MAC_ABAC_CTL" test read "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot read secret"
else
	fail "isolated should not be able to read secret (got: $OUTPUT)"
fi

run_test
info "Test: isolated cannot write secret shm"
OUTPUT=$("$MAC_ABAC_CTL" test write "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot write secret"
else
	fail "isolated should not be able to write secret (got: $OUTPUT)"
fi

run_test
info "Test: isolated can open secret shm"
OUTPUT=$("$MAC_ABAC_CTL" test open "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "isolated can open secret"
else
	fail "isolated should be able to open secret (got: $OUTPUT)"
fi

run_test
info "Test: normal process can read secret shm"
OUTPUT=$("$MAC_ABAC_CTL" test read "type=normal" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "normal can read secret"
else
	fail "normal should be able to read secret (got: $OUTPUT)"
fi

# ===========================================
# Test unlink restrictions
# ===========================================
echo ""
info "=== Unlink Restrictions ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny unlink type=user -> type=system" >/dev/null
"$MAC_ABAC_CTL" rule add "allow unlink type=admin -> *" >/dev/null
"$MAC_ABAC_CTL" default deny >/dev/null

run_test
info "Test: user cannot unlink system shm"
OUTPUT=$("$MAC_ABAC_CTL" test unlink "type=user" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "user cannot unlink system"
else
	fail "user should not be able to unlink system (got: $OUTPUT)"
fi

run_test
info "Test: admin can unlink system shm"
OUTPUT=$("$MAC_ABAC_CTL" test unlink "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin can unlink system"
else
	fail "admin should be able to unlink system (got: $OUTPUT)"
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
