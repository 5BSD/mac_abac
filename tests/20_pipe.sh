#!/bin/sh
#
# Test: Pipe Operations (read/write/stat)
#
# Tests that pipe hooks enforce access control rules.
#
# Pipe labels are inherited from the creating process credential.
# Unlike files, pipes cannot be labeled via extattr - they are
# anonymous in-memory objects. Rules can control:
#   - read: reading from pipe
#   - write: writing to pipe
#   - stat: fstat on pipe
#
# Since we can't directly label pipes, we test rule parsing and
# evaluation via vlabelctl test command.
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
echo "Pipe Operations Tests"
echo "(read/write/stat via inherited labels)"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# ===========================================
# Setup - Test rule parsing
# ===========================================
info "=== Rule Parsing ==="

# Pipes use standard read/write/stat operations - verify they work
"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: read operation in pipe context"
if "$VLABELCTL" rule add "deny read type=untrusted -> type=secret" >/dev/null 2>&1; then
	pass "read operation accepted"
else
	fail "read operation should be accepted"
fi

run_test
info "Test: write operation in pipe context"
if "$VLABELCTL" rule add "deny write type=sandbox -> *" >/dev/null 2>&1; then
	pass "write operation accepted"
else
	fail "write operation should be accepted"
fi

run_test
info "Test: stat operation in pipe context"
if "$VLABELCTL" rule add "deny stat type=restricted -> *" >/dev/null 2>&1; then
	pass "stat operation accepted"
else
	fail "stat operation should be accepted"
fi

# ===========================================
# Test pipe operations via vlabelctl test
# ===========================================
echo ""
info "=== Test Command Verification ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny read type=untrusted -> type=secret" >/dev/null
"$VLABELCTL" rule add "allow read * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: read denied for untrusted -> secret"
OUTPUT=$("$VLABELCTL" test read "type=untrusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "read denied for untrusted -> secret"
else
	fail "read should be denied for untrusted -> secret (got: $OUTPUT)"
fi

run_test
info "Test: read allowed for trusted -> secret"
OUTPUT=$("$VLABELCTL" test read "type=trusted" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "read allowed for trusted -> secret"
else
	fail "read should be allowed for trusted -> secret (got: $OUTPUT)"
fi

# ===========================================
# Test write restrictions
# ===========================================
echo ""
info "=== Write Restrictions ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny write type=sandbox -> *" >/dev/null
"$VLABELCTL" rule add "allow write * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: write denied for sandbox"
OUTPUT=$("$VLABELCTL" test write "type=sandbox" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "write denied for sandbox"
else
	fail "write should be denied for sandbox (got: $OUTPUT)"
fi

run_test
info "Test: write allowed for normal process"
OUTPUT=$("$VLABELCTL" test write "type=normal" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "write allowed for normal"
else
	fail "write should be allowed for normal (got: $OUTPUT)"
fi

# ===========================================
# Test combined read/write rules
# ===========================================
echo ""
info "=== Combined Read/Write Rules ==="

"$VLABELCTL" rule clear >/dev/null
# Isolated process: no read or write to pipes with secret label
"$VLABELCTL" rule add "deny read,write type=isolated -> type=secret" >/dev/null
# Allow all other pipe ops
"$VLABELCTL" rule add "allow read,write,stat * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: isolated cannot read secret pipe"
OUTPUT=$("$VLABELCTL" test read "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot read secret"
else
	fail "isolated should not be able to read secret (got: $OUTPUT)"
fi

run_test
info "Test: isolated cannot write secret pipe"
OUTPUT=$("$VLABELCTL" test write "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot write secret"
else
	fail "isolated should not be able to write secret (got: $OUTPUT)"
fi

run_test
info "Test: isolated can stat secret pipe (only read/write denied)"
OUTPUT=$("$VLABELCTL" test stat "type=isolated" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "isolated can stat secret"
else
	fail "isolated should be able to stat secret (got: $OUTPUT)"
fi

run_test
info "Test: normal process can read secret pipe"
OUTPUT=$("$VLABELCTL" test read "type=normal" "type=secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "normal can read secret"
else
	fail "normal should be able to read secret (got: $OUTPUT)"
fi

# ===========================================
# Test rule listing shows pipe-relevant ops
# ===========================================
echo ""
info "=== Rule Display ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny read,write,stat type=restricted -> type=sensitive" >/dev/null

run_test
info "Test: Rule list shows read/write/stat operations"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "read" && echo "$OUTPUT" | grep -q "write"; then
	pass "read/write operations displayed in rule list"
else
	fail "read/write operations should be in rule list (got: $OUTPUT)"
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
