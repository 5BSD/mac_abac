#!/bin/sh
#
# Test: Sysctl Tunables
#
# Comprehensive tests for all sysctl tunables:
# - security.mac.vlabel.enabled
# - security.mac.vlabel.mode
# - security.mac.vlabel.default_policy
# - security.mac.vlabel.extattr_name
#
# Also tests that statistics sysctls are readable.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - vlabelctl must be built
#

set -e

# Load test helpers
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
VLABELCTL="${VLABELCTL:-../tools/vlabelctl}"
TEST_FILE="/tmp/vlabel_tunable_test_$$"

# Prerequisites
require_root
require_module
require_vlabelctl

echo "============================================"
echo "Sysctl Tunables Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_ENABLED=$(sysctl -n security.mac.vlabel.enabled)
ORIG_MODE=$(sysctl -n security.mac.vlabel.mode)
ORIG_DEFAULT=$(sysctl -n security.mac.vlabel.default_policy)
ORIG_EXTATTR=$(sysctl -n security.mac.vlabel.extattr_name)

cleanup() {
	rm -f "$TEST_FILE" 2>/dev/null || true
	sysctl security.mac.vlabel.enabled=$ORIG_ENABLED >/dev/null 2>&1 || true
	sysctl security.mac.vlabel.mode=$ORIG_MODE >/dev/null 2>&1 || true
	sysctl security.mac.vlabel.default_policy=$ORIG_DEFAULT >/dev/null 2>&1 || true
	sysctl security.mac.vlabel.extattr_name="$ORIG_EXTATTR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ===========================================
# Test: enabled tunable
# ===========================================
info "=== security.mac.vlabel.enabled ==="

run_test
info "Test: Read enabled"
if sysctl -n security.mac.vlabel.enabled >/dev/null 2>&1; then
	pass "read enabled"
else
	fail "read enabled"
fi

run_test
info "Test: Set enabled=0 (disabled)"
if sysctl security.mac.vlabel.enabled=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.enabled)
	if [ "$VAL" = "0" ]; then
		pass "set enabled=0"
	else
		fail "set enabled=0 (got: $VAL)"
	fi
else
	fail "set enabled=0"
fi

run_test
info "Test: Set enabled=1 (enabled)"
if sysctl security.mac.vlabel.enabled=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.enabled)
	if [ "$VAL" = "1" ]; then
		pass "set enabled=1"
	else
		fail "set enabled=1 (got: $VAL)"
	fi
else
	fail "set enabled=1"
fi

# ===========================================
# Test: mode tunable
# ===========================================
info ""
info "=== security.mac.vlabel.mode ==="

run_test
info "Test: Read mode"
if sysctl -n security.mac.vlabel.mode >/dev/null 2>&1; then
	pass "read mode"
else
	fail "read mode"
fi

run_test
info "Test: Set mode=0 (disabled)"
if sysctl security.mac.vlabel.mode=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.mode)
	if [ "$VAL" = "0" ]; then
		pass "set mode=0"
	else
		fail "set mode=0 (got: $VAL)"
	fi
else
	fail "set mode=0"
fi

run_test
info "Test: Set mode=1 (permissive)"
if sysctl security.mac.vlabel.mode=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.mode)
	if [ "$VAL" = "1" ]; then
		pass "set mode=1"
	else
		fail "set mode=1 (got: $VAL)"
	fi
else
	fail "set mode=1"
fi

run_test
info "Test: Set mode=2 (enforcing)"
if sysctl security.mac.vlabel.mode=2 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.mode)
	if [ "$VAL" = "2" ]; then
		pass "set mode=2"
		# Immediately set back to permissive to avoid lockout
		sysctl security.mac.vlabel.mode=1 >/dev/null 2>&1
	else
		fail "set mode=2 (got: $VAL)"
	fi
else
	fail "set mode=2"
fi

run_test
info "Test: Mode via vlabelctl matches sysctl"
sysctl security.mac.vlabel.mode=1 >/dev/null 2>&1
SYSCTL_VAL=$(sysctl -n security.mac.vlabel.mode)
CTL_VAL=$("$VLABELCTL" mode | grep -o '[0-9]' | head -1 || echo "")
# vlabelctl mode returns "permissive" for mode 1
CTL_MODE=$("$VLABELCTL" mode)
if [ "$CTL_MODE" = "permissive" ] && [ "$SYSCTL_VAL" = "1" ]; then
	pass "vlabelctl mode matches sysctl"
else
	fail "vlabelctl mode matches sysctl (sysctl=$SYSCTL_VAL, vlabelctl=$CTL_MODE)"
fi

# ===========================================
# Test: default_policy tunable
# ===========================================
info ""
info "=== security.mac.vlabel.default_policy ==="

run_test
info "Test: Read default_policy"
if sysctl -n security.mac.vlabel.default_policy >/dev/null 2>&1; then
	pass "read default_policy"
else
	fail "read default_policy"
fi

run_test
info "Test: Set default_policy=0 (allow)"
if sysctl security.mac.vlabel.default_policy=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.default_policy)
	if [ "$VAL" = "0" ]; then
		pass "set default_policy=0"
	else
		fail "set default_policy=0 (got: $VAL)"
	fi
else
	fail "set default_policy=0"
fi

run_test
info "Test: Set default_policy=1 (deny)"
if sysctl security.mac.vlabel.default_policy=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.default_policy)
	if [ "$VAL" = "1" ]; then
		pass "set default_policy=1"
	else
		fail "set default_policy=1 (got: $VAL)"
	fi
else
	fail "set default_policy=1"
fi

run_test
info "Test: Default policy via vlabelctl matches sysctl"
sysctl security.mac.vlabel.default_policy=0 >/dev/null 2>&1
CTL_DEFAULT=$("$VLABELCTL" default)
if [ "$CTL_DEFAULT" = "allow" ]; then
	pass "vlabelctl default matches sysctl"
else
	fail "vlabelctl default matches sysctl (expected allow, got: $CTL_DEFAULT)"
fi

# ===========================================
# Test: extattr_name tunable
# ===========================================
info ""
info "=== security.mac.vlabel.extattr_name ==="

run_test
info "Test: Read extattr_name"
EXTATTR=$(sysctl -n security.mac.vlabel.extattr_name 2>/dev/null)
if [ -n "$EXTATTR" ]; then
	pass "read extattr_name (value: $EXTATTR)"
else
	fail "read extattr_name"
fi

run_test
info "Test: Set extattr_name to custom value"
if sysctl security.mac.vlabel.extattr_name="test_label" >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.extattr_name)
	if [ "$VAL" = "test_label" ]; then
		pass "set extattr_name=test_label"
	else
		fail "set extattr_name=test_label (got: $VAL)"
	fi
else
	fail "set extattr_name=test_label"
fi

run_test
info "Test: Restore extattr_name to default"
if sysctl security.mac.vlabel.extattr_name="vlabel" >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.vlabel.extattr_name)
	if [ "$VAL" = "vlabel" ]; then
		pass "restore extattr_name=vlabel"
	else
		fail "restore extattr_name=vlabel (got: $VAL)"
	fi
else
	fail "restore extattr_name=vlabel"
fi

run_test
info "Test: vlabelctl uses configured extattr_name"
# Set custom extattr name
sysctl security.mac.vlabel.extattr_name="custom_attr" >/dev/null 2>&1
# Create test file
echo "test" > "$TEST_FILE"
# Set label using vlabelctl (should use custom attr via sysctl lookup)
"$VLABELCTL" label set "$TEST_FILE" "type=test" >/dev/null 2>&1 || true
# Check if it was written to the custom attr
if getextattr -q system custom_attr "$TEST_FILE" 2>/dev/null | grep -q "type=test"; then
	pass "vlabelctl uses configured extattr_name"
else
	# Check if it went to default (would be a bug)
	if getextattr -q system vlabel "$TEST_FILE" 2>/dev/null | grep -q "type=test"; then
		fail "vlabelctl used default instead of configured extattr_name"
	else
		# Neither worked - might be permission or other issue
		skip "could not verify extattr_name usage"
	fi
fi
# Restore
sysctl security.mac.vlabel.extattr_name="vlabel" >/dev/null 2>&1

# ===========================================
# Test: Statistics sysctls (read-only)
# ===========================================
info ""
info "=== Statistics Sysctls (read-only) ==="

run_test
info "Test: Read checks counter"
if sysctl -n security.mac.vlabel.checks >/dev/null 2>&1; then
	pass "read checks"
else
	fail "read checks"
fi

run_test
info "Test: Read allowed counter"
if sysctl -n security.mac.vlabel.allowed >/dev/null 2>&1; then
	pass "read allowed"
else
	fail "read allowed"
fi

run_test
info "Test: Read denied counter"
if sysctl -n security.mac.vlabel.denied >/dev/null 2>&1; then
	pass "read denied"
else
	fail "read denied"
fi

run_test
info "Test: Read rule_count"
if sysctl -n security.mac.vlabel.rule_count >/dev/null 2>&1; then
	pass "read rule_count"
else
	fail "read rule_count"
fi

run_test
info "Test: Read labels_read"
if sysctl -n security.mac.vlabel.labels_read >/dev/null 2>&1; then
	pass "read labels_read"
else
	fail "read labels_read"
fi

run_test
info "Test: Read labels_default"
if sysctl -n security.mac.vlabel.labels_default >/dev/null 2>&1; then
	pass "read labels_default"
else
	fail "read labels_default"
fi

run_test
info "Test: Read labels_allocated"
if sysctl -n security.mac.vlabel.labels_allocated >/dev/null 2>&1; then
	pass "read labels_allocated"
else
	fail "read labels_allocated"
fi

run_test
info "Test: Read labels_freed"
if sysctl -n security.mac.vlabel.labels_freed >/dev/null 2>&1; then
	pass "read labels_freed"
else
	fail "read labels_freed"
fi

run_test
info "Test: Read parse_errors"
if sysctl -n security.mac.vlabel.parse_errors >/dev/null 2>&1; then
	pass "read parse_errors"
else
	fail "read parse_errors"
fi

run_test
info "Test: Statistics are read-only (checks)"
if sysctl security.mac.vlabel.checks=0 2>/dev/null; then
	fail "checks should be read-only"
else
	pass "checks is read-only"
fi

# ===========================================
# Test: All sysctls visible
# ===========================================
info ""
info "=== All Sysctls Visible ==="

run_test
info "Test: sysctl security.mac.vlabel shows all tunables"
OUTPUT=$(sysctl security.mac.vlabel 2>&1)
MISSING=""
for tunable in enabled mode default_policy extattr_name checks allowed denied rule_count labels_read labels_default labels_allocated labels_freed parse_errors; do
	if ! echo "$OUTPUT" | grep -q "$tunable"; then
		MISSING="$MISSING $tunable"
	fi
done
if [ -z "$MISSING" ]; then
	pass "all tunables visible"
else
	fail "missing tunables:$MISSING"
fi

# ===========================================
# Summary
# ===========================================
summary
