#!/bin/sh
#
# Test: Context Constraints (Comprehensive)
#
# Tests all combinations of context constraints:
# 1. Rules without any context (regression - should work as before)
# 2. Rules with subj_context only
# 3. Rules with obj_context only
# 4. Rules with both subj_context and obj_context
# 5. Jail-based object context
# 6. UID-based context constraints
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
TEST_DIR="/root/vlabel_context_constraint_test_$$"

# Check prerequisites
require_root
require_vlabelctl

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	pkill -f "vlabel_context_constraint_test" 2>/dev/null || true
	"$VLABELCTL" mode permissive >/dev/null 2>&1 || true
	"$VLABELCTL" rule clear >/dev/null 2>&1 || true
	"$VLABELCTL" default allow >/dev/null 2>&1 || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Context Constraints Comprehensive Tests"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"

# ===========================================
# Build helper programs
# ===========================================
info "=== Building Test Programs ==="

# Simple debugger helper (no capmode)
cat > "$TEST_DIR/debugger.c" << 'EOF'
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
	pid_t pid;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return 3;
	}
	pid = atoi(argv[1]);

	ret = ptrace(PT_ATTACH, pid, 0, 0);
	if (ret < 0) {
		int err = errno;
		fprintf(stderr, "ptrace failed: %s (errno=%d)\n", strerror(err), err);
		return (err == EPERM || err == EACCES) ? 1 : 3;
	}

	waitpid(pid, NULL, 0);
	ptrace(PT_DETACH, pid, 0, 0);
	fprintf(stderr, "ptrace succeeded\n");
	return 0;
}
EOF

cc -o "$TEST_DIR/debugger" "$TEST_DIR/debugger.c"
pass "Debugger compiled"

# Target that sleeps
cat > "$TEST_DIR/target.c" << 'EOF'
#include <unistd.h>
int main(void) { sleep(300); return 0; }
EOF

cc -o "$TEST_DIR/target" "$TEST_DIR/target.c"
pass "Target compiled"

# Target that enters capability mode
cat > "$TEST_DIR/capmode_target.c" << 'EOF'
#include <sys/capsicum.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {
	if (cap_enter() < 0) {
		fprintf(stderr, "cap_enter: %s\n", strerror(errno));
		return 1;
	}
	fprintf(stderr, "capmode PID=%d\n", getpid());
	fflush(stderr);
	sleep(300);
	return 0;
}
EOF

cc -o "$TEST_DIR/capmode_target" "$TEST_DIR/capmode_target.c"
pass "Capmode target compiled"

# ===========================================
# Test 1: Rules WITHOUT context (regression)
# ===========================================
echo ""
info "=== Test 1: Rules Without Context (Regression) ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# When a process execs a labeled binary, it inherits the vnode label.
# No transition rule needed - this is automatic.
#
# Rules:
# 1. Deny debug to type=secret processes
# 2. Allow everything else

"$VLABELCTL" rule add "deny debug * -> type=secret"
"$VLABELCTL" rule add "allow all * -> *"

# Label the binary - process will inherit this label on exec
"$VLABELCTL" label set "$TEST_DIR/target" "type=secret"

info "Rules (no context constraints):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 1a: Label-only deny rule works (process inherits vnode label)"
set +e
"$TEST_DIR/debugger" "$TARGET_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Denied by label-only rule (no context)"
else
	fail "Should be denied (exit=$EXIT_CODE)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

# Remove label and try again - should succeed (unlabeled = inherit parent)
"$VLABELCTL" label set "$TEST_DIR/target" ""
"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 1b: Unlabeled target can be debugged"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Allowed (no matching deny rule)"
else
	fail "Should be allowed"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Test 2: subj_context ONLY
# ===========================================
echo ""
info "=== Test 2: Subject Context Only ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# Deny debug if caller is root (uid=0) - we ARE root, so this should deny
"$VLABELCTL" rule add "deny debug * -> * subj_context:uid=0"
"$VLABELCTL" rule add "allow all * -> *"

info "Rules (subj_context:uid=0):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 2a: subj_context:uid=0 denies root"
set +e
"$TEST_DIR/debugger" "$TARGET_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Root denied by subj_context:uid=0"
else
	fail "Root should be denied (exit=$EXIT_CODE)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

# Now test with uid=9999 (not us) - should allow
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny debug * -> * subj_context:uid=9999"
"$VLABELCTL" rule add "allow all * -> *"

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 2b: subj_context:uid=9999 allows root"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Root allowed (uid doesn't match 9999)"
else
	fail "Root should be allowed"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Test 3: obj_context ONLY
# ===========================================
echo ""
info "=== Test 3: Object Context Only ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# Deny debug if TARGET is in capability mode
"$VLABELCTL" rule add "deny debug * -> * obj_context:sandboxed=true"
"$VLABELCTL" rule add "allow all * -> *"

info "Rules (obj_context:sandboxed=true):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

# Start capmode target
"$TEST_DIR/capmode_target" &
CAPMODE_PID=$!
sleep 1

run_test
info "Test 3a: obj_context:sandboxed=true denies debug of capmode process"
set +e
"$TEST_DIR/debugger" "$CAPMODE_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Denied debug of capmode target"
else
	fail "Should be denied (exit=$EXIT_CODE)"
fi

kill $CAPMODE_PID 2>/dev/null || true
wait $CAPMODE_PID 2>/dev/null || true

# Normal target should be allowed
"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 3b: Normal target can be debugged"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Normal target allowed"
else
	fail "Should be allowed"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Test 4: BOTH subj_context AND obj_context
# ===========================================
echo ""
info "=== Test 4: Both Subject and Object Context ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# Deny if: caller is root AND target is in capmode
# Both conditions must be true
"$VLABELCTL" rule add "deny debug * -> * subj_context:uid=0 obj_context:sandboxed=true"
"$VLABELCTL" rule add "allow all * -> *"

info "Rules (subj_context:uid=0 AND obj_context:sandboxed=true):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

# Start capmode target
"$TEST_DIR/capmode_target" &
CAPMODE_PID=$!
sleep 1

run_test
info "Test 4a: Both conditions true -> DENY"
set +e
"$TEST_DIR/debugger" "$CAPMODE_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Denied (root debugging capmode target)"
else
	fail "Should be denied (exit=$EXIT_CODE)"
fi

kill $CAPMODE_PID 2>/dev/null || true
wait $CAPMODE_PID 2>/dev/null || true

# Normal target - obj_context doesn't match, should ALLOW
"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 4b: Only subj_context true (target not capmode) -> ALLOW"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Allowed (target not in capmode, rule doesn't match)"
else
	fail "Should be allowed (obj_context doesn't match)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Test 5: obj_context with jail (simulation)
# ===========================================
echo ""
info "=== Test 5: Object Context Jail Check ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# Deny debug if target is on host (jail=host means jail_id=0)
# Since we're on host and target is on host, this should deny
"$VLABELCTL" rule add "deny debug * -> * obj_context:jail=host"
"$VLABELCTL" rule add "allow all * -> *"

info "Rules (obj_context:jail=host):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 5a: obj_context:jail=host denies debug of host process"
set +e
"$TEST_DIR/debugger" "$TARGET_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Denied debug of host process"
else
	fail "Should be denied (exit=$EXIT_CODE)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

# Now use jail=any - target is NOT in jail, so should ALLOW
"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny debug * -> * obj_context:jail=any"
"$VLABELCTL" rule add "allow all * -> *"

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 5b: obj_context:jail=any allows debug of host process"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Allowed (target not in jail)"
else
	fail "Should be allowed (target not in any jail)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Test 6: Verify rule display shows contexts
# ===========================================
echo ""
info "=== Test 6: Rule Display Verification ==="

"$VLABELCTL" rule clear >/dev/null

"$VLABELCTL" rule add "deny debug * -> * subj_context:uid=0,jail=host"
"$VLABELCTL" rule add "deny signal * -> * obj_context:sandboxed=true"
"$VLABELCTL" rule add "deny sched * -> * subj_context:jail=any obj_context:jail=host"

run_test
info "Test 6: Rules display context constraints correctly"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
echo "$OUTPUT"

ERRORS=0

if echo "$OUTPUT" | grep -q "subj_context:.*uid=0"; then
	pass "subj_context:uid displayed"
else
	fail "subj_context:uid not displayed"
	ERRORS=$((ERRORS + 1))
fi

if echo "$OUTPUT" | grep -q "subj_context:.*jail=host"; then
	pass "subj_context:jail displayed"
else
	fail "subj_context:jail not displayed"
	ERRORS=$((ERRORS + 1))
fi

if echo "$OUTPUT" | grep -q "obj_context:.*sandboxed=true"; then
	pass "obj_context:sandboxed displayed"
else
	fail "obj_context:sandboxed not displayed"
	ERRORS=$((ERRORS + 1))
fi

if echo "$OUTPUT" | grep -q "subj_context:.*jail=any.*obj_context:.*jail=host"; then
	pass "Both contexts displayed on same rule"
else
	fail "Both contexts not displayed correctly"
	ERRORS=$((ERRORS + 1))
fi

# ===========================================
# Test 7: Backward compatibility (context: alias)
# ===========================================
echo ""
info "=== Test 7: Backward Compatibility (context: alias) ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" default allow

# Use old 'context:' syntax (should work as subj_context:)
"$VLABELCTL" rule add "deny debug * -> * context:uid=0"
"$VLABELCTL" rule add "allow all * -> *"

info "Rules (using deprecated context: syntax):"
"$VLABELCTL" rule list

"$VLABELCTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 7: Deprecated 'context:' works as subj_context"
set +e
"$TEST_DIR/debugger" "$TARGET_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Deprecated context: syntax works"
else
	fail "Should be denied (exit=$EXIT_CODE)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$VLABELCTL" mode permissive

# ===========================================
# Summary
# ===========================================

"$VLABELCTL" mode permissive >/dev/null 2>&1
"$VLABELCTL" rule clear >/dev/null 2>&1
"$VLABELCTL" default allow >/dev/null 2>&1

summary
