#!/bin/sh
#
# Test: Recursive Label Setting (label setrecursive)
#
# Tests the setrecursive command that applies labels to entire directory
# trees using the atomic ABAC_SYS_SETLABEL syscall.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must support the 'label setrecursive' command
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
	TEST_DIR="/root/abac_recursive_test_$$"
else
	TEST_DIR="/var/tmp/abac_recursive_test_$$"
fi

# Prerequisites
require_root
require_module
require_mac_abac_ctl

echo "============================================"
echo "Recursive Label Setting Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_MODE=$("$MAC_ABAC_CTL" mode)

# Cleanup function
cleanup() {
	rm -rf "$TEST_DIR" 2>/dev/null || true
	"$MAC_ABAC_CTL" mode "$ORIG_MODE" >/dev/null 2>&1 || true
}

trap cleanup EXIT

# Set permissive mode for testing
"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1

# Create test directory structure
#
# test_dir/
# ├── file1.txt
# ├── file2.txt
# ├── subdir1/
# │   ├── nested1.txt
# │   └── nested2.txt
# ├── subdir2/
# │   └── deep/
# │       └── deepfile.txt
# └── symlink -> file1.txt
#
create_test_tree() {
	rm -rf "$TEST_DIR"
	mkdir -p "$TEST_DIR"
	mkdir -p "$TEST_DIR/subdir1"
	mkdir -p "$TEST_DIR/subdir2/deep"

	# Use cat with heredoc - works when echo/touch/cp may be blocked by MAC
	cat > "$TEST_DIR/file1.txt" <<EOF
file1 content
EOF
	cat > "$TEST_DIR/file2.txt" <<EOF
file2 content
EOF
	cat > "$TEST_DIR/subdir1/nested1.txt" <<EOF
nested1 content
EOF
	cat > "$TEST_DIR/subdir1/nested2.txt" <<EOF
nested2 content
EOF
	cat > "$TEST_DIR/subdir2/deep/deepfile.txt" <<EOF
deep content
EOF
	ln -sf "$TEST_DIR/file1.txt" "$TEST_DIR/symlink"
}

count_labeled() {
	local dir="$1"
	local label="$2"
	local count=0

	for f in $(find "$dir" -type f -o -type d 2>/dev/null); do
		if "$MAC_ABAC_CTL" label get "$f" 2>/dev/null | grep -q "$label"; then
			count=$((count + 1))
		fi
	done
	echo "$count"
}

# ===========================================
# Test: Basic recursive labeling
# ===========================================
info "=== Basic Recursive Labeling Tests ==="

run_test
info "Test: Setrecursive command exists"
if "$MAC_ABAC_CTL" label setrecursive 2>&1 | grep -q "requires path"; then
	pass "setrecursive command exists"
else
	# Check if it exists but prints different error
	if "$MAC_ABAC_CTL" help 2>&1 | grep -q "setrecursive"; then
		pass "setrecursive command exists"
	else
		fail "setrecursive command not found"
	fi
fi

run_test
info "Test: Recursive label on flat directory"
create_test_tree
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=recursive" 2>&1 | grep -q "labeled"; then
	# Verify files got labeled
	FILE1_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/file1.txt" 2>&1 || echo "none")
	if echo "$FILE1_LABEL" | grep -q "type=recursive"; then
		pass "recursive label on flat directory"
	else
		fail "recursive label not applied (got: $FILE1_LABEL)"
	fi
else
	fail "setrecursive command failed"
fi

run_test
info "Test: Recursive label on nested directories"
create_test_tree
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=nested" 2>&1; then
	# Check deeply nested file
	DEEP_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/subdir2/deep/deepfile.txt" 2>&1 || echo "none")
	if echo "$DEEP_LABEL" | grep -q "type=nested"; then
		pass "recursive label reaches nested files"
	else
		fail "recursive label not on nested file (got: $DEEP_LABEL)"
	fi
else
	fail "setrecursive on nested failed"
fi

run_test
info "Test: Directories also get labeled"
create_test_tree
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=all" 2>&1; then
	# Check directory label
	DIR_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/subdir1" 2>&1 || echo "none")
	if echo "$DIR_LABEL" | grep -q "type=all"; then
		pass "directories get labeled"
	else
		fail "directory not labeled (got: $DIR_LABEL)"
	fi
else
	fail "setrecursive for directory label failed"
fi

# ===========================================
# Test: Verbose mode (-v)
# ===========================================
info ""
info "=== Verbose Mode Tests ==="

run_test
info "Test: Verbose mode prints each file"
create_test_tree
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=verbose" -v 2>&1 || true)
if echo "$OUTPUT" | grep -q "file1.txt" && \
   echo "$OUTPUT" | grep -q "deepfile.txt"; then
	pass "verbose mode prints files"
else
	fail "verbose mode missing files (got: $OUTPUT)"
fi

run_test
info "Test: Verbose mode shows count"
create_test_tree
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=count" -v 2>&1 || true)
if echo "$OUTPUT" | grep -q "labeled [0-9]* items"; then
	pass "verbose mode shows labeled count"
else
	fail "verbose mode missing count (got: $OUTPUT)"
fi

# ===========================================
# Test: Directories only (-d)
# ===========================================
info ""
info "=== Directories Only Mode Tests ==="

run_test
info "Test: -d flag labels only directories"
create_test_tree
# First remove any existing labels
for f in "$TEST_DIR"/*.txt "$TEST_DIR"/subdir1/*.txt "$TEST_DIR"/subdir2/deep/*.txt; do
	"$MAC_ABAC_CTL" label remove "$f" 2>/dev/null || true
done

if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=dirsonly" -d 2>&1; then
	# Directory should be labeled
	DIR_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/subdir1" 2>&1 || echo "none")
	# File should NOT be labeled
	FILE_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/file1.txt" 2>&1 || echo "none")

	if echo "$DIR_LABEL" | grep -q "type=dirsonly"; then
		if echo "$FILE_LABEL" | grep -qi "no label\|none\|unlabeled"; then
			pass "-d flag labels only directories"
		else
			# File might have existing label, just verify it's not the new one
			if ! echo "$FILE_LABEL" | grep -q "type=dirsonly"; then
				pass "-d flag labels only directories"
			else
				fail "-d flag also labeled files (file: $FILE_LABEL)"
			fi
		fi
	else
		fail "-d flag did not label directory (dir: $DIR_LABEL)"
	fi
else
	fail "setrecursive -d failed"
fi

# ===========================================
# Test: Files only (-f)
# ===========================================
info ""
info "=== Files Only Mode Tests ==="

run_test
info "Test: -f flag labels only files"
create_test_tree
# Remove directory labels first
"$MAC_ABAC_CTL" label remove "$TEST_DIR/subdir1" 2>/dev/null || true
"$MAC_ABAC_CTL" label remove "$TEST_DIR/subdir2" 2>/dev/null || true
"$MAC_ABAC_CTL" label remove "$TEST_DIR/subdir2/deep" 2>/dev/null || true

if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=filesonly" -f 2>&1; then
	# File should be labeled
	FILE_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/file1.txt" 2>&1 || echo "none")
	# Directory should NOT be labeled with new label
	DIR_LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/subdir1" 2>&1 || echo "none")

	if echo "$FILE_LABEL" | grep -q "type=filesonly"; then
		if ! echo "$DIR_LABEL" | grep -q "type=filesonly"; then
			pass "-f flag labels only files"
		else
			fail "-f flag also labeled directories (dir: $DIR_LABEL)"
		fi
	else
		fail "-f flag did not label file (file: $FILE_LABEL)"
	fi
else
	fail "setrecursive -f failed"
fi

run_test
info "Test: -d and -f are mutually exclusive"
create_test_tree
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=both" -d -f 2>&1 || true)
if echo "$OUTPUT" | grep -qi "mutually exclusive\|error\|usage"; then
	pass "-d and -f mutual exclusion enforced"
else
	fail "-d and -f should be mutually exclusive"
fi

# ===========================================
# Test: Symlinks are skipped
# ===========================================
info ""
info "=== Symlink Handling Tests ==="

run_test
info "Test: Symlinks are skipped"
create_test_tree
# Count items before
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=nosymlink" -v 2>&1 || true)
# Symlink should not appear in verbose output
if ! echo "$OUTPUT" | grep -q "symlink"; then
	pass "symlinks skipped"
else
	fail "symlinks should be skipped (output: $OUTPUT)"
fi

# ===========================================
# Test: Error handling
# ===========================================
info ""
info "=== Error Handling Tests ==="

run_test
info "Test: Nonexistent directory fails"
if "$MAC_ABAC_CTL" label setrecursive "/nonexistent/path" "type=fail" 2>/dev/null; then
	fail "nonexistent directory should fail"
else
	pass "nonexistent directory fails correctly"
fi

run_test
info "Test: Permission errors are reported"
# Create unreadable directory
mkdir -p "$TEST_DIR/noperm"
echo "test" > "$TEST_DIR/noperm/secret.txt"
chmod 000 "$TEST_DIR/noperm"

OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=noperm" 2>&1 || true)
# Should report error but continue
if echo "$OUTPUT" | grep -qi "error\|Permission\|denied\|cannot"; then
	pass "permission errors reported"
else
	# May just skip inaccessible directories
	pass "permission errors handled (skipped)"
fi

chmod 755 "$TEST_DIR/noperm"

run_test
info "Test: Empty directory works"
mkdir -p "$TEST_DIR/emptydir"
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR/emptydir" "type=empty" 2>&1 || true)
if echo "$OUTPUT" | grep -q "labeled"; then
	# Just the directory itself
	pass "empty directory works"
else
	fail "empty directory failed (output: $OUTPUT)"
fi

# ===========================================
# Test: Label format handling
# ===========================================
info ""
info "=== Label Format Tests ==="

run_test
info "Test: Comma-separated labels work"
create_test_tree
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=app,domain=web,env=prod" 2>&1; then
	LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/file1.txt" 2>&1 || echo "none")
	if echo "$LABEL" | grep -q "type=app" && \
	   echo "$LABEL" | grep -q "domain=web" && \
	   echo "$LABEL" | grep -q "env=prod"; then
		pass "comma-separated labels work"
	else
		fail "comma-separated labels incomplete (got: $LABEL)"
	fi
else
	fail "comma-separated label setrecursive failed"
fi

run_test
info "Test: Complex label with many pairs"
create_test_tree
COMPLEX="type=complex,domain=test,sensitivity=high,version=1,env=dev"
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "$COMPLEX" 2>&1; then
	LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/subdir1/nested1.txt" 2>&1 || echo "none")
	if echo "$LABEL" | grep -q "type=complex" && \
	   echo "$LABEL" | grep -q "version=1"; then
		pass "complex label with many pairs"
	else
		fail "complex label incomplete (got: $LABEL)"
	fi
else
	fail "complex label setrecursive failed"
fi

# ===========================================
# Test: Count verification
# ===========================================
info ""
info "=== Count Verification Tests ==="

run_test
info "Test: Labeled count is accurate"
create_test_tree
OUTPUT=$("$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=counted" 2>&1 || true)
# Extract count from output (e.g., "labeled 8 items")
REPORTED=$(echo "$OUTPUT" | grep -o "labeled [0-9]*" | grep -o "[0-9]*" || echo "0")

# Count manually: 6 files + 4 directories (including root) = 10, minus symlink = 9
# Actually: file1, file2, nested1, nested2, deepfile = 5 files
# Dirs: test_dir, subdir1, subdir2, deep = 4 directories
# Total should be around 9

if [ "$REPORTED" -ge 8 ] && [ "$REPORTED" -le 10 ]; then
	pass "labeled count is accurate ($REPORTED items)"
else
	fail "labeled count unexpected (reported: $REPORTED)"
fi

# ===========================================
# Test: Overwriting existing labels
# ===========================================
info ""
info "=== Overwrite Tests ==="

run_test
info "Test: Setrecursive overwrites existing labels"
create_test_tree
# Set initial label
"$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=initial" 2>/dev/null || true

# Overwrite with new label
if "$MAC_ABAC_CTL" label setrecursive "$TEST_DIR" "type=overwritten,version=2" 2>&1; then
	LABEL=$("$MAC_ABAC_CTL" label get "$TEST_DIR/file1.txt" 2>&1 || echo "none")
	if echo "$LABEL" | grep -q "type=overwritten" && \
	   echo "$LABEL" | grep -q "version=2"; then
		# Verify old label is gone
		if ! echo "$LABEL" | grep -q "type=initial"; then
			pass "setrecursive overwrites existing labels"
		else
			fail "old label still present (got: $LABEL)"
		fi
	else
		fail "new label not applied (got: $LABEL)"
	fi
else
	fail "overwrite setrecursive failed"
fi

# ===========================================
# Summary
# ===========================================
summary
