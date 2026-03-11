#!/bin/sh
#
# Test: SysV Semaphore Operations
#
# Tests that SysV semaphore hooks enforce access control rules.
#
# Semaphore labels are inherited from the creating process credential.
# Like other IPC objects, semaphores cannot be labeled via extattr - they
# are in-memory objects. Rules can control:
#   - open: semget()
#   - read: semop() with SEM_R (read access)
#   - write: semop() with SEM_A (alter access)
#   - stat: semctl(IPC_STAT, GETVAL, GETPID, GETNCNT, GETZCNT, GETALL)
#   - write: semctl(IPC_SET, IPC_RMID, SETVAL, SETALL)
#
# Since we can't directly label semaphores, we test rule parsing and
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
echo "SysV Semaphore Tests"
echo "(open/read/write/stat)"
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
info "Test: open operation for semget"
if "$VLABELCTL" rule add "deny open type=untrusted -> type=sem_critical" >/dev/null 2>&1; then
	pass "open operation accepted"
else
	fail "open operation should be accepted"
fi

run_test
info "Test: read operation for semop(SEM_R)"
if "$VLABELCTL" rule add "deny read type=sandbox -> type=sem_sensitive" >/dev/null 2>&1; then
	pass "read operation accepted"
else
	fail "read operation should be accepted"
fi

run_test
info "Test: write operation for semop(SEM_A)"
if "$VLABELCTL" rule add "deny write type=untrusted -> type=sem_system" >/dev/null 2>&1; then
	pass "write operation accepted"
else
	fail "write operation should be accepted"
fi

# ===========================================
# Test semget access control
# ===========================================
echo ""
info "=== Semaphore Access (semget) ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny open type=untrusted -> type=sem_critical" >/dev/null
"$VLABELCTL" rule add "allow open * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: untrusted cannot open critical semaphore"
OUTPUT=$("$VLABELCTL" test open "type=untrusted" "type=sem_critical" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "untrusted cannot open critical semaphore"
else
	fail "untrusted should not open critical semaphore (got: $OUTPUT)"
fi

run_test
info "Test: trusted can open critical semaphore"
OUTPUT=$("$VLABELCTL" test open "type=trusted" "type=sem_critical" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "trusted can open critical semaphore"
else
	fail "trusted should open critical semaphore (got: $OUTPUT)"
fi

# ===========================================
# Test semop access control (read vs alter)
# ===========================================
echo ""
info "=== Semaphore Operations (semop) ==="

"$VLABELCTL" rule clear >/dev/null
# Worker can read semaphore value but not alter
"$VLABELCTL" rule add "allow read type=worker -> type=sem_job" >/dev/null
"$VLABELCTL" rule add "deny write type=worker -> type=sem_job" >/dev/null
# Coordinator can both read and alter
"$VLABELCTL" rule add "allow read,write type=coordinator -> type=sem_job" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: worker can read job semaphore"
OUTPUT=$("$VLABELCTL" test read "type=worker" "type=sem_job" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "worker can read job semaphore"
else
	fail "worker should read job semaphore (got: $OUTPUT)"
fi

run_test
info "Test: worker cannot alter job semaphore"
OUTPUT=$("$VLABELCTL" test write "type=worker" "type=sem_job" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "worker cannot alter job semaphore"
else
	fail "worker should not alter job semaphore (got: $OUTPUT)"
fi

run_test
info "Test: coordinator can read job semaphore"
OUTPUT=$("$VLABELCTL" test read "type=coordinator" "type=sem_job" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "coordinator can read job semaphore"
else
	fail "coordinator should read job semaphore (got: $OUTPUT)"
fi

run_test
info "Test: coordinator can alter job semaphore"
OUTPUT=$("$VLABELCTL" test write "type=coordinator" "type=sem_job" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "coordinator can alter job semaphore"
else
	fail "coordinator should alter job semaphore (got: $OUTPUT)"
fi

# ===========================================
# Test semctl stat/write operations
# ===========================================
echo ""
info "=== Semaphore Control (semctl) ==="

"$VLABELCTL" rule clear >/dev/null
# Monitor can stat but not modify
"$VLABELCTL" rule add "allow stat type=monitor -> type=sem_system" >/dev/null
"$VLABELCTL" rule add "deny write type=monitor -> type=sem_system" >/dev/null
# Admin can do everything
"$VLABELCTL" rule add "allow stat,write type=admin -> type=sem_system" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: monitor can stat system semaphore"
OUTPUT=$("$VLABELCTL" test stat "type=monitor" "type=sem_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "monitor can stat system semaphore"
else
	fail "monitor should stat system semaphore (got: $OUTPUT)"
fi

run_test
info "Test: monitor cannot modify system semaphore"
OUTPUT=$("$VLABELCTL" test write "type=monitor" "type=sem_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "monitor cannot modify system semaphore"
else
	fail "monitor should not modify system semaphore (got: $OUTPUT)"
fi

run_test
info "Test: admin can stat system semaphore"
OUTPUT=$("$VLABELCTL" test stat "type=admin" "type=sem_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin can stat system semaphore"
else
	fail "admin should stat system semaphore (got: $OUTPUT)"
fi

run_test
info "Test: admin can modify system semaphore"
OUTPUT=$("$VLABELCTL" test write "type=admin" "type=sem_system" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "admin can modify system semaphore"
else
	fail "admin should modify system semaphore (got: $OUTPUT)"
fi

# ===========================================
# Test multi-process synchronization scenario
# ===========================================
echo ""
info "=== Multi-Process Synchronization Scenario ==="

"$VLABELCTL" rule clear >/dev/null
# Producer/consumer pattern
"$VLABELCTL" rule add "allow read,write type=producer -> type=sem_buffer" >/dev/null
"$VLABELCTL" rule add "allow read,write type=consumer -> type=sem_buffer" >/dev/null
# Isolate different buffer types
"$VLABELCTL" rule add "deny read,write type=producer -> type=sem_log" >/dev/null
"$VLABELCTL" rule add "allow read,write type=logger -> type=sem_log" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: producer can access buffer semaphore"
OUTPUT=$("$VLABELCTL" test write "type=producer" "type=sem_buffer" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "producer can access buffer semaphore"
else
	fail "producer should access buffer semaphore (got: $OUTPUT)"
fi

run_test
info "Test: consumer can access buffer semaphore"
OUTPUT=$("$VLABELCTL" test read "type=consumer" "type=sem_buffer" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "consumer can access buffer semaphore"
else
	fail "consumer should access buffer semaphore (got: $OUTPUT)"
fi

run_test
info "Test: producer cannot access log semaphore"
OUTPUT=$("$VLABELCTL" test write "type=producer" "type=sem_log" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "producer cannot access log semaphore"
else
	fail "producer should not access log semaphore (got: $OUTPUT)"
fi

run_test
info "Test: logger can access log semaphore"
OUTPUT=$("$VLABELCTL" test write "type=logger" "type=sem_log" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "logger can access log semaphore"
else
	fail "logger should access log semaphore (got: $OUTPUT)"
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
