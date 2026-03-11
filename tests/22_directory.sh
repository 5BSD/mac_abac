#!/bin/sh
#
# Test: Directory & Metadata Operations
#
# Tests that directory and metadata hooks enforce access control rules.
#
# Operations tested:
#   - chdir: cd into directory
#   - readdir: list directory contents
#   - lookup: name resolution
#   - create: creating files in directory
#   - link: creating hard links
#   - rename: renaming files
#   - unlink: deleting files
#   - stat: file status
#   - setmode/setowner/setutimes: metadata modification (via write)
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
echo "Directory & Metadata Operation Tests"
echo "(chdir/readdir/lookup/create/link/rename/"
echo " unlink/stat/setmode/setowner/setutimes)"
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
info "Test: chdir operation"
if "$MAC_ABAC_CTL" rule add "deny chdir type=restricted -> type=protected" >/dev/null 2>&1; then
	pass "chdir operation accepted"
else
	fail "chdir operation should be accepted"
fi

run_test
info "Test: readdir operation"
if "$MAC_ABAC_CTL" rule add "deny readdir type=untrusted -> type=secret" >/dev/null 2>&1; then
	pass "readdir operation accepted"
else
	fail "readdir operation should be accepted"
fi

run_test
info "Test: lookup operation"
if "$MAC_ABAC_CTL" rule add "deny lookup type=sandbox -> type=system" >/dev/null 2>&1; then
	pass "lookup operation accepted"
else
	fail "lookup operation should be accepted"
fi

run_test
info "Test: create operation"
if "$MAC_ABAC_CTL" rule add "deny create type=guest -> type=admin" >/dev/null 2>&1; then
	pass "create operation accepted"
else
	fail "create operation should be accepted"
fi

run_test
info "Test: link operation"
if "$MAC_ABAC_CTL" rule add "deny link type=user -> type=protected" >/dev/null 2>&1; then
	pass "link operation accepted"
else
	fail "link operation should be accepted"
fi

run_test
info "Test: rename operation"
if "$MAC_ABAC_CTL" rule add "deny rename type=reader -> type=important" >/dev/null 2>&1; then
	pass "rename operation accepted"
else
	fail "rename operation should be accepted"
fi

run_test
info "Test: unlink operation"
if "$MAC_ABAC_CTL" rule add "deny unlink type=guest -> type=critical" >/dev/null 2>&1; then
	pass "unlink operation accepted"
else
	fail "unlink operation should be accepted"
fi

run_test
info "Test: stat operation"
if "$MAC_ABAC_CTL" rule add "deny stat type=lowpriv -> type=secret" >/dev/null 2>&1; then
	pass "stat operation accepted"
else
	fail "stat operation should be accepted"
fi

# ===========================================
# Test directory operations via mac_abac_ctl test
# ===========================================
echo ""
info "=== Directory Access Rules ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny chdir type=restricted -> type=protected" >/dev/null
"$MAC_ABAC_CTL" rule add "allow chdir * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: chdir denied for restricted -> protected"
OUTPUT=$("$MAC_ABAC_CTL" test chdir "type=restricted" "type=protected" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "chdir denied for restricted -> protected"
else
	fail "chdir should be denied for restricted -> protected (got: $OUTPUT)"
fi

run_test
info "Test: chdir allowed for normal -> protected"
OUTPUT=$("$MAC_ABAC_CTL" test chdir "type=normal" "type=protected" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "chdir allowed for normal -> protected"
else
	fail "chdir should be allowed for normal -> protected (got: $OUTPUT)"
fi

# ===========================================
# Test readdir restrictions
# ===========================================
echo ""
info "=== ReadDir Restrictions ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny readdir type=untrusted -> type=secret" >/dev/null
"$MAC_ABAC_CTL" rule add "allow readdir * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: readdir denied for untrusted -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test readdir "type=untrusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "readdir denied for untrusted -> secret"
else
	fail "readdir should be denied for untrusted -> secret (got: $OUTPUT)"
fi

run_test
info "Test: readdir allowed for trusted -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test readdir "type=trusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "readdir allowed for trusted -> secret"
else
	fail "readdir should be allowed for trusted -> secret (got: $OUTPUT)"
fi

# ===========================================
# Test lookup restrictions
# ===========================================
echo ""
info "=== Lookup Restrictions ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny lookup type=sandbox -> type=system" >/dev/null
"$MAC_ABAC_CTL" rule add "allow lookup * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: lookup denied for sandbox -> system"
OUTPUT=$("$MAC_ABAC_CTL" test lookup "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "lookup denied for sandbox -> system"
else
	fail "lookup should be denied for sandbox -> system (got: $OUTPUT)"
fi

run_test
info "Test: lookup allowed for admin -> system"
OUTPUT=$("$MAC_ABAC_CTL" test lookup "type=admin" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "lookup allowed for admin -> system"
else
	fail "lookup should be allowed for admin -> system (got: $OUTPUT)"
fi

# ===========================================
# Test file manipulation operations
# ===========================================
echo ""
info "=== File Manipulation ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny create type=guest -> type=admin" >/dev/null
"$MAC_ABAC_CTL" rule add "deny link type=user -> type=protected" >/dev/null
"$MAC_ABAC_CTL" rule add "deny rename type=reader -> type=important" >/dev/null
"$MAC_ABAC_CTL" rule add "deny unlink type=guest -> type=critical" >/dev/null
"$MAC_ABAC_CTL" rule add "allow create,link,rename,unlink * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: create denied for guest -> admin"
OUTPUT=$("$MAC_ABAC_CTL" test create "type=guest" "type=admin" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "create denied for guest -> admin"
else
	fail "create should be denied for guest -> admin (got: $OUTPUT)"
fi

run_test
info "Test: link denied for user -> protected"
OUTPUT=$("$MAC_ABAC_CTL" test link "type=user" "type=protected" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "link denied for user -> protected"
else
	fail "link should be denied for user -> protected (got: $OUTPUT)"
fi

run_test
info "Test: rename denied for reader -> important"
OUTPUT=$("$MAC_ABAC_CTL" test rename "type=reader" "type=important" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "rename denied for reader -> important"
else
	fail "rename should be denied for reader -> important (got: $OUTPUT)"
fi

run_test
info "Test: unlink denied for guest -> critical"
OUTPUT=$("$MAC_ABAC_CTL" test unlink "type=guest" "type=critical" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "unlink denied for guest -> critical"
else
	fail "unlink should be denied for guest -> critical (got: $OUTPUT)"
fi

run_test
info "Test: unlink allowed for admin -> critical"
OUTPUT=$("$MAC_ABAC_CTL" test unlink "type=admin" "type=critical" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "unlink allowed for admin -> critical"
else
	fail "unlink should be allowed for admin -> critical (got: $OUTPUT)"
fi

# ===========================================
# Test stat restrictions
# ===========================================
echo ""
info "=== Stat Restrictions ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny stat type=lowpriv -> type=secret" >/dev/null
"$MAC_ABAC_CTL" rule add "allow stat * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: stat denied for lowpriv -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test stat "type=lowpriv" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "stat denied for lowpriv -> secret"
else
	fail "stat should be denied for lowpriv -> secret (got: $OUTPUT)"
fi

run_test
info "Test: stat allowed for highpriv -> secret"
OUTPUT=$("$MAC_ABAC_CTL" test stat "type=highpriv" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "stat allowed for highpriv -> secret"
else
	fail "stat should be allowed for highpriv -> secret (got: $OUTPUT)"
fi

# ===========================================
# Test combined operations
# ===========================================
echo ""
info "=== Combined Operations ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
# Protect system directories from sandboxed processes
"$MAC_ABAC_CTL" rule add "deny chdir,readdir,lookup type=sandbox -> type=system" >/dev/null
# Allow normal access
"$MAC_ABAC_CTL" rule add "allow chdir,readdir,lookup,create,link,rename,unlink,stat * -> *" >/dev/null
"$MAC_ABAC_CTL" default allow >/dev/null

run_test
info "Test: sandbox cannot chdir to system"
OUTPUT=$("$MAC_ABAC_CTL" test chdir "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot chdir to system"
else
	fail "sandbox should not be able to chdir to system (got: $OUTPUT)"
fi

run_test
info "Test: sandbox cannot readdir system"
OUTPUT=$("$MAC_ABAC_CTL" test readdir "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot readdir system"
else
	fail "sandbox should not be able to readdir system (got: $OUTPUT)"
fi

run_test
info "Test: sandbox cannot lookup in system"
OUTPUT=$("$MAC_ABAC_CTL" test lookup "type=sandbox" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot lookup in system"
else
	fail "sandbox should not be able to lookup in system (got: $OUTPUT)"
fi

run_test
info "Test: normal can access system dirs"
OUTPUT=$("$MAC_ABAC_CTL" test chdir "type=normal" "type=system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "normal can access system dirs"
else
	fail "normal should be able to access system dirs (got: $OUTPUT)"
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
