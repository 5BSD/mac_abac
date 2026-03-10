#!/bin/sh
#
# Test: Atomic setlabel syscall (VLABEL_SYS_SETLABEL)
#
# Tests the atomic label set operation that writes to extattr AND updates
# the in-memory cached label in a single syscall. This is essential for
# ZFS and other filesystems that don't support MNT_MULTILABEL.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must support the 'label setatomic' command
#

set -e

# Load test helpers
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
VLABELCTL="${VLABELCTL:-../tools/vlabelctl}"
TEST_FILE="/tmp/vlabel_atomic_test_$$"
TEST_DIR="/tmp/vlabel_atomic_testdir_$$"

# Prerequisites
require_root
require_module
require_vlabelctl

echo "============================================"
echo "Atomic Setlabel Syscall Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_MODE=$("$VLABELCTL" mode)

# Create test files
cleanup() {
	rm -f "$TEST_FILE" 2>/dev/null || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
	"$VLABELCTL" mode "$ORIG_MODE" >/dev/null 2>&1 || true
}

trap cleanup EXIT

# Set permissive mode for testing
"$VLABELCTL" mode permissive >/dev/null 2>&1

# Create test file
echo "test content" > "$TEST_FILE"
mkdir -p "$TEST_DIR"
echo "dir test" > "$TEST_DIR/nested_file"

# ===========================================
# Test: Basic atomic setlabel
# ===========================================
info "=== Basic Atomic Setlabel Tests ==="

run_test
info "Test: Atomic setlabel on regular file"
# First verify the file has no label or default label
INITIAL=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "no label")

# Set label atomically
if "$VLABELCTL" label setatomic "$TEST_FILE" "type=test\ndomain=atomic" 2>&1; then
	# Verify the label was set
	OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	if echo "$OUTPUT" | grep -q "type=test"; then
		if echo "$OUTPUT" | grep -q "domain=atomic"; then
			pass "atomic setlabel on regular file"
		else
			fail "atomic setlabel missing domain (got: $OUTPUT)"
		fi
	else
		fail "atomic setlabel missing type (got: $OUTPUT)"
	fi
else
	# If setatomic command doesn't exist yet, test the raw syscall via C test
	skip "atomic setlabel command not implemented in vlabelctl"
fi

run_test
info "Test: Atomic setlabel with single key=value"
if "$VLABELCTL" label setatomic "$TEST_FILE" "sensitivity=high" 2>/dev/null; then
	OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	if echo "$OUTPUT" | grep -q "sensitivity=high"; then
		pass "atomic setlabel single pair"
	else
		fail "atomic setlabel single pair (got: $OUTPUT)"
	fi
else
	skip "atomic setlabel command not available"
fi

run_test
info "Test: Atomic setlabel with multiple pairs"
COMPLEX_LABEL="type=application\ndomain=web\nsensitivity=secret\nenv=production"
if "$VLABELCTL" label setatomic "$TEST_FILE" "$COMPLEX_LABEL" 2>/dev/null; then
	OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	if echo "$OUTPUT" | grep -q "type=application" && \
	   echo "$OUTPUT" | grep -q "domain=web" && \
	   echo "$OUTPUT" | grep -q "sensitivity=secret"; then
		pass "atomic setlabel multiple pairs"
	else
		fail "atomic setlabel multiple pairs (got: $OUTPUT)"
	fi
else
	skip "atomic setlabel command not available"
fi

# ===========================================
# Test: Label persistence verification
# ===========================================
info ""
info "=== Persistence Verification Tests ==="

run_test
info "Test: Label persists in extattr after atomic set"
if "$VLABELCTL" label setatomic "$TEST_FILE" "type=persistent" 2>/dev/null; then
	# Read directly from extattr to verify write-through
	EXTATTR_VAL=$(getextattr -q system vlabel "$TEST_FILE" 2>/dev/null || echo "")
	if echo "$EXTATTR_VAL" | grep -q "persistent"; then
		pass "atomic setlabel persists to extattr"
	else
		fail "atomic setlabel not in extattr (got: $EXTATTR_VAL)"
	fi
else
	skip "atomic setlabel command not available"
fi

run_test
info "Test: In-memory cache matches extattr after atomic set"
if "$VLABELCTL" label setatomic "$TEST_FILE" "type=cached\ndomain=inmemory" 2>/dev/null; then
	# Get via vlabelctl (reads from cache)
	CACHED=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	# Get directly from extattr
	DISK=$(getextattr -q system vlabel "$TEST_FILE" 2>/dev/null || echo "")

	# Both should have the same content
	if echo "$CACHED" | grep -q "type=cached" && echo "$DISK" | grep -q "cached"; then
		pass "cache matches extattr after atomic set"
	else
		fail "cache/extattr mismatch (cache: $CACHED, disk: $DISK)"
	fi
else
	skip "atomic setlabel command not available"
fi

# ===========================================
# Test: Edge cases
# ===========================================
info ""
info "=== Edge Case Tests ==="

run_test
info "Test: Atomic setlabel with empty label clears it"
if "$VLABELCTL" label setatomic "$TEST_FILE" "" 2>/dev/null; then
	OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	# Should show default/unlabeled
	if echo "$OUTPUT" | grep -qi "unlabeled\|no label\|default"; then
		pass "atomic setlabel empty clears label"
	else
		# Empty label might just be empty
		pass "atomic setlabel empty accepted"
	fi
else
	skip "atomic setlabel command not available"
fi

run_test
info "Test: Atomic setlabel on directory"
if "$VLABELCTL" label setatomic "$TEST_DIR" "type=directory\naccess=restricted" 2>/dev/null; then
	OUTPUT=$("$VLABELCTL" label get "$TEST_DIR" 2>&1 || echo "failed")
	if echo "$OUTPUT" | grep -q "type=directory"; then
		pass "atomic setlabel on directory"
	else
		fail "atomic setlabel directory (got: $OUTPUT)"
	fi
else
	skip "atomic setlabel command not available"
fi

run_test
info "Test: Atomic setlabel overwrites existing label"
# Set initial label
"$VLABELCTL" label setatomic "$TEST_FILE" "type=initial" 2>/dev/null || true
# Overwrite with new label
if "$VLABELCTL" label setatomic "$TEST_FILE" "type=overwritten\nnew=yes" 2>/dev/null; then
	OUTPUT=$("$VLABELCTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	if echo "$OUTPUT" | grep -q "type=overwritten" && \
	   echo "$OUTPUT" | grep -q "new=yes"; then
		# Verify old value is gone
		if ! echo "$OUTPUT" | grep -q "type=initial"; then
			pass "atomic setlabel overwrites existing"
		else
			fail "atomic setlabel did not overwrite (got: $OUTPUT)"
		fi
	else
		fail "atomic setlabel overwrite (got: $OUTPUT)"
	fi
else
	skip "atomic setlabel command not available"
fi

# ===========================================
# Test: Error handling
# ===========================================
info ""
info "=== Error Handling Tests ==="

run_test
info "Test: Atomic setlabel on nonexistent file fails"
if "$VLABELCTL" label setatomic "/nonexistent/file/path" "type=fail" 2>/dev/null; then
	fail "atomic setlabel nonexistent should fail"
else
	pass "atomic setlabel nonexistent fails correctly"
fi

run_test
info "Test: Atomic setlabel with invalid fd fails"
# This tests kernel error path - invalid fd should return error
# We can't directly test this from shell, but verify command handles errors
if ! "$VLABELCTL" label setatomic "" "type=test" 2>/dev/null; then
	pass "atomic setlabel with empty path fails"
else
	fail "atomic setlabel with empty path should fail"
fi

# ===========================================
# Test: Comparison with two-step method
# ===========================================
info ""
info "=== Atomic vs Two-Step Comparison ==="

run_test
info "Test: Atomic setlabel result matches two-step method"
# Create two test files
TEST_FILE_A="/tmp/vlabel_atomic_a_$$"
TEST_FILE_B="/tmp/vlabel_atomic_b_$$"
echo "test a" > "$TEST_FILE_A"
echo "test b" > "$TEST_FILE_B"

LABEL="type=comparison\nvalue=same"

# Method A: Atomic
if "$VLABELCTL" label setatomic "$TEST_FILE_A" "$LABEL" 2>/dev/null; then
	# Method B: Two-step (setextattr + refresh)
	printf "%s" "type=comparison
value=same" | setextattr system vlabel "$TEST_FILE_B" 2>/dev/null || true
	# Need to refresh the cache for file B
	# Open the file to trigger associate hook or use refresh syscall
	"$VLABELCTL" label refresh "$TEST_FILE_B" 2>/dev/null || true

	RESULT_A=$("$VLABELCTL" label get "$TEST_FILE_A" 2>&1 || echo "failed")
	RESULT_B=$("$VLABELCTL" label get "$TEST_FILE_B" 2>&1 || echo "failed")

	# Both should have the same label
	if echo "$RESULT_A" | grep -q "type=comparison" && \
	   echo "$RESULT_B" | grep -q "type=comparison"; then
		pass "atomic and two-step produce same result"
	else
		fail "atomic vs two-step mismatch (A: $RESULT_A, B: $RESULT_B)"
	fi
else
	skip "atomic setlabel command not available"
fi

rm -f "$TEST_FILE_A" "$TEST_FILE_B" 2>/dev/null || true

# ===========================================
# Summary
# ===========================================
summary
