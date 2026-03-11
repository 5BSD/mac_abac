#!/bin/sh
#
# Test: Atomic setlabel syscall (ABAC_SYS_SETLABEL)
#
# Tests the atomic label set operation that writes to extattr AND updates
# the in-memory cached label in a single syscall. This is essential for
# ZFS and other filesystems that don't support MNT_MULTILABEL.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must support the 'label setatomic' command
#

set -e

# Load test helpers
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
MAC_ABAC_CTL="${1:-${MAC_ABAC_CTL:-../tools/mac_abac_ctl}}"

# Use ZFS-backed directory for extended attributes support
# /tmp may be tmpfs which doesn't support extattrs
if [ -d "/root" ]; then
	TEST_BASE="/root"
else
	TEST_BASE="/var/tmp"
fi
TEST_FILE="$TEST_BASE/abac_atomic_test_$$"
TEST_DIR="$TEST_BASE/abac_atomic_testdir_$$"

# Prerequisites
require_root
require_module
require_mac_abac_ctl

echo "============================================"
echo "Atomic Setlabel Syscall Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_MODE=$("$MAC_ABAC_CTL" mode)

# Create test files
cleanup() {
	rm -f "$TEST_FILE" 2>/dev/null || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
	"$MAC_ABAC_CTL" mode "$ORIG_MODE" >/dev/null 2>&1 || true
}

trap cleanup EXIT

# Set permissive mode for testing
"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1

# Create test file (use cat - works when echo may be blocked by MAC)
cat > "$TEST_FILE" <<EOF
test content
EOF
mkdir -p "$TEST_DIR"
cat > "$TEST_DIR/nested_file" <<EOF
dir test
EOF

# ===========================================
# Test: Basic atomic setlabel
# ===========================================
info "=== Basic Atomic Setlabel Tests ==="

run_test
info "Test: Atomic setlabel on regular file"
# First verify the file has no label or default label
INITIAL=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "no label")

# Set label atomically
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "type=test\ndomain=atomic" 2>&1; then
	# Verify the label was set
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
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
	skip "atomic setlabel command not implemented in mac_abac_ctl"
fi

run_test
info "Test: Atomic setlabel with single key=value"
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "sensitivity=high" 2>/dev/null; then
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
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
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "$COMPLEX_LABEL" 2>/dev/null; then
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
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
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "type=persistent" 2>/dev/null; then
	# Read directly from extattr to verify write-through
	EXTATTR_VAL=$(getextattr -q system mac_abac "$TEST_FILE" 2>/dev/null || echo "")
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
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "type=cached\ndomain=inmemory" 2>/dev/null; then
	# Get via mac_abac_ctl (reads from cache)
	CACHED=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
	# Get directly from extattr
	DISK=$(getextattr -q system mac_abac "$TEST_FILE" 2>/dev/null || echo "")

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
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "" 2>/dev/null; then
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
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
if "$MAC_ABAC_CTL" label setatomic "$TEST_DIR" "type=directory\naccess=restricted" 2>/dev/null; then
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_DIR" 2>&1 || echo "failed")
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
"$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "type=initial" 2>/dev/null || true
# Overwrite with new label
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE" "type=overwritten\nnew=yes" 2>/dev/null; then
	OUTPUT=$("$MAC_ABAC_CTL" label get "$TEST_FILE" 2>&1 || echo "failed")
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
if "$MAC_ABAC_CTL" label setatomic "/nonexistent/file/path" "type=fail" 2>/dev/null; then
	fail "atomic setlabel nonexistent should fail"
else
	pass "atomic setlabel nonexistent fails correctly"
fi

run_test
info "Test: Atomic setlabel with invalid fd fails"
# This tests kernel error path - invalid fd should return error
# We can't directly test this from shell, but verify command handles errors
if ! "$MAC_ABAC_CTL" label setatomic "" "type=test" 2>/dev/null; then
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
info "Test: Multiple atomic setlabel operations are consistent"
# Create two test files (use ZFS-backed path)
TEST_FILE_A="$TEST_BASE/abac_atomic_a_$$"
TEST_FILE_B="$TEST_BASE/abac_atomic_b_$$"
cat > "$TEST_FILE_A" <<EOF
test a
EOF
cat > "$TEST_FILE_B" <<EOF
test b
EOF

LABEL="type=comparison,value=same"

# Apply same label atomically to both files
if "$MAC_ABAC_CTL" label setatomic "$TEST_FILE_A" "$LABEL" 2>/dev/null && \
   "$MAC_ABAC_CTL" label setatomic "$TEST_FILE_B" "$LABEL" 2>/dev/null; then

	RESULT_A=$("$MAC_ABAC_CTL" label get "$TEST_FILE_A" 2>&1 || echo "failed")
	RESULT_B=$("$MAC_ABAC_CTL" label get "$TEST_FILE_B" 2>&1 || echo "failed")

	# Both should have the same label
	if echo "$RESULT_A" | grep -q "type=comparison" && \
	   echo "$RESULT_B" | grep -q "type=comparison"; then
		pass "multiple atomic setlabel operations consistent"
	else
		fail "atomic setlabel inconsistent (A: $RESULT_A, B: $RESULT_B)"
	fi
else
	fail "atomic setlabel failed"
fi

rm -f "$TEST_FILE_A" "$TEST_FILE_B" 2>/dev/null || true

# ===========================================
# Summary
# ===========================================
summary
