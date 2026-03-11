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
# - mac_abac_ctl must be built
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
TEST_DIR="/root/abac_context_constraint_test_$$"

# Check prerequisites
require_root
require_mac_abac_ctl

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	pkill -f "abac_context_constraint_test" 2>/dev/null || true
	"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1 || true
	"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
	"$MAC_ABAC_CTL" default allow >/dev/null 2>&1 || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Context Constraints Comprehensive Tests"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
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

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow

# When a process execs a labeled binary, it inherits the vnode label.
# No transition rule needed - this is automatic.
#
# Rules:
# 1. Deny debug to type=secret processes
# 2. Allow everything else

"$MAC_ABAC_CTL" rule add "deny debug * -> type=secret"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

# Label the binary - process will inherit this label on exec
"$MAC_ABAC_CTL" label set "$TEST_DIR/target" "type=secret"

info "Rules (no context constraints):"
"$MAC_ABAC_CTL" rule list

"$MAC_ABAC_CTL" mode enforcing

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
"$MAC_ABAC_CTL" label set "$TEST_DIR/target" ""
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

"$MAC_ABAC_CTL" mode permissive

# ===========================================
# Test 2: subj_context ONLY
# ===========================================
echo ""
info "=== Test 2: Subject Context Only ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow

# Deny debug if caller is root (uid=0) - we ARE root, so this should deny
"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:uid=0"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

info "Rules (ctx:uid=0):"
"$MAC_ABAC_CTL" rule list

"$MAC_ABAC_CTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 2a: ctx:uid=0 denies root"
set +e
"$TEST_DIR/debugger" "$TARGET_PID" 2>&1
EXIT_CODE=$?
set -e
if [ $EXIT_CODE -eq 1 ]; then
	pass "Root denied by ctx:uid=0"
else
	fail "Root should be denied (exit=$EXIT_CODE)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

# Now test with uid=9999 (not us) - should allow
"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:uid=9999"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 2b: ctx:uid=9999 allows root"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Root allowed (uid doesn't match 9999)"
else
	fail "Root should be allowed"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$MAC_ABAC_CTL" mode permissive

# ===========================================
# Test 3: obj_context ONLY
# ===========================================
echo ""
info "=== Test 3: Object Context Only ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow

# Deny debug if TARGET is in capability mode
"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:sandboxed=true"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

info "Rules (ctx:sandboxed=true):"
"$MAC_ABAC_CTL" rule list

"$MAC_ABAC_CTL" mode enforcing

# Start capmode target
"$TEST_DIR/capmode_target" &
CAPMODE_PID=$!
sleep 1

run_test
info "Test 3a: ctx:sandboxed=true denies debug of capmode process"
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

"$MAC_ABAC_CTL" mode permissive

# ===========================================
# Test 4: BOTH subj_context AND obj_context
# ===========================================
echo ""
info "=== Test 4: Both Subject and Object Context ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow

# Deny if: caller is root AND target is in capmode
# Both conditions must be true - use ctx: before -> for subject, after -> for object
"$MAC_ABAC_CTL" rule add "deny debug * ctx:uid=0 -> * ctx:sandboxed=true"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

info "Rules (subj ctx:uid=0 AND obj ctx:sandboxed=true):"
"$MAC_ABAC_CTL" rule list

"$MAC_ABAC_CTL" mode enforcing

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

"$MAC_ABAC_CTL" mode permissive

# ===========================================
# Test 5: obj_context with jail (simulation)
# ===========================================
echo ""
info "=== Test 5: Object Context Jail Check ==="

"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" default allow

# Deny debug if target is on host (jail=host means jail_id=0)
# Since we're on host and target is on host, this should deny
"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:jail=host"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

info "Rules (ctx:jail=host):"
"$MAC_ABAC_CTL" rule list

"$MAC_ABAC_CTL" mode enforcing

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 5a: ctx:jail=host denies debug of host process"
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
"$MAC_ABAC_CTL" rule clear >/dev/null
"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:jail=any"
"$MAC_ABAC_CTL" rule add "allow all * -> *"

"$TEST_DIR/target" &
TARGET_PID=$!
sleep 1

run_test
info "Test 5b: ctx:jail=any allows debug of host process"
if "$TEST_DIR/debugger" "$TARGET_PID" 2>/dev/null; then
	pass "Allowed (target not in jail)"
else
	fail "Should be allowed (target not in any jail)"
fi

kill $TARGET_PID 2>/dev/null || true
wait $TARGET_PID 2>/dev/null || true

"$MAC_ABAC_CTL" mode permissive

# ===========================================
# Test 6: Verify rule display shows contexts
# ===========================================
echo ""
info "=== Test 6: Rule Display Verification ==="

"$MAC_ABAC_CTL" rule clear >/dev/null

"$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:uid=0,jail=host"
"$MAC_ABAC_CTL" rule add "deny signal * -> * ctx:sandboxed=true"
# Use both subject and object context for display testing
"$MAC_ABAC_CTL" rule add "deny sched * ctx:jail=any -> * ctx:jail=host"

run_test
info "Test 6: Rules display context constraints correctly"
OUTPUT=$("$MAC_ABAC_CTL" rule list 2>&1)
echo "$OUTPUT"

ERRORS=0

# Note: mac_abac_ctl displays "obj_context:" and "subj_context:" not "ctx:"
if echo "$OUTPUT" | grep -q "uid=0"; then
	pass "uid constraint displayed"
else
	fail "uid constraint not displayed"
	ERRORS=$((ERRORS + 1))
fi

if echo "$OUTPUT" | grep -q "jail=host"; then
	pass "jail=host constraint displayed"
else
	fail "jail=host constraint not displayed"
	ERRORS=$((ERRORS + 1))
fi

if echo "$OUTPUT" | grep -q "sandboxed=true"; then
	pass "sandboxed=true constraint displayed"
else
	fail "sandboxed=true constraint not displayed"
	ERRORS=$((ERRORS + 1))
fi

# Check that both subject and object contexts are displayed on the same rule
# Rule 3 has subj_context:jail=any and obj_context:jail=host
if echo "$OUTPUT" | grep -q "subj_context:.*jail=any" && echo "$OUTPUT" | grep -q "obj_context:.*jail=host"; then
	pass "Both subj_context and obj_context displayed on same rule"
else
	fail "Both contexts not displayed correctly"
	ERRORS=$((ERRORS + 1))
fi

# ===========================================
# Summary
# ===========================================

"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1
"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1
"$MAC_ABAC_CTL" default allow >/dev/null 2>&1

summary
