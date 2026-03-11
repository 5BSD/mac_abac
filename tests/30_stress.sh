#!/bin/sh
#
# 30_stress.sh - Stress tests and leak detection for mac_abac
#
# Performs repeated operations to expose:
# - Memory leaks
# - Race conditions
# - Resource exhaustion
# - Stability issues
#
# Usage: ./30_stress.sh [mac_abac_ctl_path]
#

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

MAC_ABAC_CTL="${1:-/usr/local/sbin/mac_abac_ctl}"
ITERATIONS="${ABAC_STRESS_ITERS:-100}"
TMPDIR="${TMPDIR:-/tmp}"
TESTDIR="$TMPDIR/abac_stress_$$"

require_root
require_module

info "Running stress tests ($ITERATIONS iterations)"

cleanup() {
    rm -rf "$TESTDIR" 2>/dev/null || true
}

mkdir -p "$TESTDIR"

# Capture initial state
INITIAL_KMEM=$(vmstat -m 2>/dev/null | tail -1 | awk '{print $3}' || echo "0")
INITIAL_ZONES=$(vmstat -z 2>/dev/null | grep -i mac_abac | awk '{sum += $4} END {print sum+0}' || echo "0")

# -----------------------------------------------------------------------------
# Test 1: Repeated status queries
# -----------------------------------------------------------------------------
run_test
info "Stress test: repeated status queries..."
FAIL_COUNT=0
i=0
while [ $i -lt $ITERATIONS ]; do
    if ! $MAC_ABAC_CTL status >/dev/null 2>&1; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    i=$((i + 1))
done
if [ $FAIL_COUNT -eq 0 ]; then
    pass "Status queries ($ITERATIONS iterations)"
else
    fail "Status queries had $FAIL_COUNT failures"
fi

# -----------------------------------------------------------------------------
# Test 2: Repeated rule list queries
# -----------------------------------------------------------------------------
run_test
info "Stress test: repeated rule list queries..."
FAIL_COUNT=0
i=0
while [ $i -lt $ITERATIONS ]; do
    if ! $MAC_ABAC_CTL rule list >/dev/null 2>&1; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    i=$((i + 1))
done
if [ $FAIL_COUNT -eq 0 ]; then
    pass "Rule list queries ($ITERATIONS iterations)"
else
    fail "Rule list queries had $FAIL_COUNT failures"
fi

# -----------------------------------------------------------------------------
# Test 3: Rapid file labeling/unlabeling
# -----------------------------------------------------------------------------
run_test
info "Stress test: rapid file label operations..."
TESTFILE="$TESTDIR/labeltest"
touch "$TESTFILE"
FAIL_COUNT=0
i=0
while [ $i -lt $ITERATIONS ]; do
    # Set label
    if ! $MAC_ABAC_CTL label set "$TESTFILE" "stress=test$i" 2>/dev/null; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    # Get label
    if ! $MAC_ABAC_CTL label get "$TESTFILE" >/dev/null 2>&1; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    i=$((i + 1))
done
rm -f "$TESTFILE"
if [ $FAIL_COUNT -eq 0 ]; then
    pass "File label operations ($ITERATIONS iterations)"
else
    fail "File label operations had $FAIL_COUNT failures"
fi

# -----------------------------------------------------------------------------
# Test 4: Many files with labels
# -----------------------------------------------------------------------------
run_test
info "Stress test: labeling many files..."
FILE_COUNT=$((ITERATIONS / 2))
if [ $FILE_COUNT -gt 200 ]; then
    FILE_COUNT=200
fi
FAIL_COUNT=0
i=0
while [ $i -lt $FILE_COUNT ]; do
    TESTFILE="$TESTDIR/file_$i"
    touch "$TESTFILE"
    if ! $MAC_ABAC_CTL label set "$TESTFILE" "batch=file$i" 2>/dev/null; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    i=$((i + 1))
done
if [ $FAIL_COUNT -eq 0 ]; then
    pass "Batch file labeling ($FILE_COUNT files)"
else
    fail "Batch file labeling had $FAIL_COUNT failures"
fi

# Verify all labels readable
run_test
FAIL_COUNT=0
i=0
while [ $i -lt $FILE_COUNT ]; do
    TESTFILE="$TESTDIR/file_$i"
    if ! $MAC_ABAC_CTL label get "$TESTFILE" >/dev/null 2>&1; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    i=$((i + 1))
done
if [ $FAIL_COUNT -eq 0 ]; then
    pass "Batch file label read ($FILE_COUNT files)"
else
    fail "Batch file label read had $FAIL_COUNT failures"
fi

# -----------------------------------------------------------------------------
# Test 5: Concurrent operations (if possible)
# -----------------------------------------------------------------------------
run_test
info "Stress test: concurrent operations..."
PIDS=""
CONCURRENT=5
c=0
while [ $c -lt $CONCURRENT ]; do
    (
        j=0
        while [ $j -lt 20 ]; do
            $MAC_ABAC_CTL status >/dev/null 2>&1
            $MAC_ABAC_CTL rule list >/dev/null 2>&1
            j=$((j + 1))
        done
    ) &
    PIDS="$PIDS $!"
    c=$((c + 1))
done
FAIL_COUNT=0
for PID in $PIDS; do
    if ! wait $PID; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done
if [ $FAIL_COUNT -eq 0 ]; then
    pass "Concurrent operations ($CONCURRENT workers)"
else
    fail "Concurrent operations had $FAIL_COUNT worker failures"
fi

# -----------------------------------------------------------------------------
# Test 6: Invalid input handling
# -----------------------------------------------------------------------------
run_test
info "Stress test: invalid input handling..."
FAIL_COUNT=0
# These should all fail gracefully, not crash
$MAC_ABAC_CTL label set "/nonexistent/path" "test=label" 2>/dev/null && FAIL_COUNT=$((FAIL_COUNT + 1))
$MAC_ABAC_CTL label get "/nonexistent/path" 2>/dev/null && FAIL_COUNT=$((FAIL_COUNT + 1))
$MAC_ABAC_CTL label set "$TESTDIR" "" 2>/dev/null && FAIL_COUNT=$((FAIL_COUNT + 1))

# Very long label
LONG_LABEL=$(printf 'x%.0s' $(seq 1 1000))
$MAC_ABAC_CTL label set "$TESTDIR" "$LONG_LABEL" 2>/dev/null && FAIL_COUNT=$((FAIL_COUNT + 1))

# Module should still be responsive
if $MAC_ABAC_CTL status >/dev/null 2>&1; then
    pass "Invalid input handling (module stable)"
else
    fail "Module became unresponsive after invalid input"
fi

# -----------------------------------------------------------------------------
# Memory comparison
# -----------------------------------------------------------------------------
run_test
info "Checking for memory growth..."
sleep 1

FINAL_KMEM=$(vmstat -m 2>/dev/null | tail -1 | awk '{print $3}' || echo "0")
FINAL_ZONES=$(vmstat -z 2>/dev/null | grep -i mac_abac | awk '{sum += $4} END {print sum+0}' || echo "0")

KMEM_DIFF=$((FINAL_KMEM - INITIAL_KMEM))
ZONE_DIFF=$((FINAL_ZONES - INITIAL_ZONES))

info "Kernel memory delta: $KMEM_DIFF bytes"
info "UMA zone allocation delta: $ZONE_DIFF"

# Allow some growth but flag large increases
if [ $KMEM_DIFF -gt 1048576 ]; then
    warn "Significant kernel memory growth detected (>1MB)"
    fail "Potential memory leak: $KMEM_DIFF bytes growth"
else
    pass "Memory growth within acceptable bounds"
fi

# -----------------------------------------------------------------------------
# Final stability check
# -----------------------------------------------------------------------------
run_test
info "Final stability check..."
if $MAC_ABAC_CTL status >/dev/null 2>&1; then
    pass "Module stable after stress tests"
else
    fail "Module unstable after stress tests"
fi

# Check for new kernel errors
NEW_ERRORS=$(dmesg | tail -50 | grep -i "mac_abac" | grep -iE "error|panic|fault" || true)
if [ -z "$NEW_ERRORS" ]; then
    pass "No new kernel errors after stress"
else
    warn "New kernel messages after stress:"
    echo "$NEW_ERRORS"
    fail "Kernel errors detected after stress"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
summary
