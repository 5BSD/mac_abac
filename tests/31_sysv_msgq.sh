#!/bin/sh
#
# Test: SysV Message Queue Operations
#
# Tests that SysV message queue hooks enforce access control rules.
#
# Message queue labels are inherited from the creating process credential.
# Like pipes, message queues cannot be labeled via extattr - they are
# in-memory objects. Rules can control:
#   - open: msgget()
#   - read: msgrcv()
#   - write: msgsnd()
#   - stat: msgctl(IPC_STAT)
#   - unlink: msgctl(IPC_RMID)
#
# Since we can't directly label message queues, we test rule parsing and
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
echo "SysV Message Queue Tests"
echo "(open/read/write/stat/unlink)"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# ===========================================
# Setup - Test rule parsing
# ===========================================
info "=== Rule Parsing ==="

"$VLABELCTL" rule clear >/dev/null

run_test
info "Test: open operation for msgget"
if "$VLABELCTL" rule add "deny open type=untrusted -> type=ipc_secret" >/dev/null 2>&1; then
	pass "open operation accepted"
else
	fail "open operation should be accepted"
fi

run_test
info "Test: read operation for msgrcv"
if "$VLABELCTL" rule add "deny read type=sandbox -> type=ipc_sensitive" >/dev/null 2>&1; then
	pass "read operation accepted"
else
	fail "read operation should be accepted"
fi

run_test
info "Test: write operation for msgsnd"
if "$VLABELCTL" rule add "deny write type=untrusted -> type=ipc_trusted" >/dev/null 2>&1; then
	pass "write operation accepted"
else
	fail "write operation should be accepted"
fi

# ===========================================
# Test msgget access control
# ===========================================
echo ""
info "=== Message Queue Access (msgget) ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny open type=untrusted -> type=ipc_secret" >/dev/null
"$VLABELCTL" rule add "allow open * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: untrusted cannot open secret queue"
OUTPUT=$("$VLABELCTL" test open "type=untrusted" "type=ipc_secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "untrusted cannot open secret queue"
else
	fail "untrusted should not open secret queue (got: $OUTPUT)"
fi

run_test
info "Test: trusted can open secret queue"
OUTPUT=$("$VLABELCTL" test open "type=trusted" "type=ipc_secret" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "trusted can open secret queue"
else
	fail "trusted should open secret queue (got: $OUTPUT)"
fi

# ===========================================
# Test msgsnd/msgrcv access control
# ===========================================
echo ""
info "=== Message Send/Receive (msgsnd/msgrcv) ==="

"$VLABELCTL" rule clear >/dev/null
# Sandbox cannot send to sensitive queues
"$VLABELCTL" rule add "deny write type=sandbox -> type=ipc_sensitive" >/dev/null
# Sandbox cannot receive from sensitive queues
"$VLABELCTL" rule add "deny read type=sandbox -> type=ipc_sensitive" >/dev/null
"$VLABELCTL" rule add "allow read,write * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: sandbox cannot send to sensitive queue"
OUTPUT=$("$VLABELCTL" test write "type=sandbox" "type=ipc_sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot send to sensitive queue"
else
	fail "sandbox should not send to sensitive queue (got: $OUTPUT)"
fi

run_test
info "Test: sandbox cannot receive from sensitive queue"
OUTPUT=$("$VLABELCTL" test read "type=sandbox" "type=ipc_sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "sandbox cannot receive from sensitive queue"
else
	fail "sandbox should not receive from sensitive queue (got: $OUTPUT)"
fi

run_test
info "Test: trusted can send to sensitive queue"
OUTPUT=$("$VLABELCTL" test write "type=trusted" "type=ipc_sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "trusted can send to sensitive queue"
else
	fail "trusted should send to sensitive queue (got: $OUTPUT)"
fi

run_test
info "Test: trusted can receive from sensitive queue"
OUTPUT=$("$VLABELCTL" test read "type=trusted" "type=ipc_sensitive" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "trusted can receive from sensitive queue"
else
	fail "trusted should receive from sensitive queue (got: $OUTPUT)"
fi

# ===========================================
# Test msgctl access control
# ===========================================
echo ""
info "=== Message Control (msgctl) ==="

"$VLABELCTL" rule clear >/dev/null
# Users cannot stat system queues
"$VLABELCTL" rule add "deny stat type=user -> type=ipc_system" >/dev/null
# Users cannot remove system queues
"$VLABELCTL" rule add "deny unlink type=user -> type=ipc_system" >/dev/null
# Admin can do anything
"$VLABELCTL" rule add "allow stat,unlink type=admin -> *" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: user cannot stat system queue"
OUTPUT=$("$VLABELCTL" test stat "type=user" "type=ipc_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "user cannot stat system queue"
else
	fail "user should not stat system queue (got: $OUTPUT)"
fi

run_test
info "Test: user cannot remove system queue"
OUTPUT=$("$VLABELCTL" test unlink "type=user" "type=ipc_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "user cannot remove system queue"
else
	fail "user should not remove system queue (got: $OUTPUT)"
fi

run_test
info "Test: admin can stat system queue"
OUTPUT=$("$VLABELCTL" test stat "type=admin" "type=ipc_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin can stat system queue"
else
	fail "admin should stat system queue (got: $OUTPUT)"
fi

run_test
info "Test: admin can remove system queue"
OUTPUT=$("$VLABELCTL" test unlink "type=admin" "type=ipc_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin can remove system queue"
else
	fail "admin should remove system queue (got: $OUTPUT)"
fi

# ===========================================
# Test domain isolation
# ===========================================
echo ""
info "=== Domain Isolation ==="

"$VLABELCTL" rule clear >/dev/null
# Each domain can only access its own queues
"$VLABELCTL" rule add "allow open,read,write domain=web -> domain=web" >/dev/null
"$VLABELCTL" rule add "allow open,read,write domain=db -> domain=db" >/dev/null
"$VLABELCTL" rule add "deny open,read,write domain=web -> domain=db" >/dev/null
"$VLABELCTL" rule add "deny open,read,write domain=db -> domain=web" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: web domain can access web queues"
OUTPUT=$("$VLABELCTL" test write "domain=web" "domain=web" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "web can access web queues"
else
	fail "web should access web queues (got: $OUTPUT)"
fi

run_test
info "Test: web domain cannot access db queues"
OUTPUT=$("$VLABELCTL" test write "domain=web" "domain=db" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "web cannot access db queues"
else
	fail "web should not access db queues (got: $OUTPUT)"
fi

run_test
info "Test: db domain can access db queues"
OUTPUT=$("$VLABELCTL" test read "domain=db" "domain=db" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "db can access db queues"
else
	fail "db should access db queues (got: $OUTPUT)"
fi

run_test
info "Test: db domain cannot access web queues"
OUTPUT=$("$VLABELCTL" test read "domain=db" "domain=web" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "db cannot access web queues"
else
	fail "db should not access web queues (got: $OUTPUT)"
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
