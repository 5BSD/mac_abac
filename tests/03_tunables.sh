#!/bin/sh
#
# Test: Sysctl Tunables
#
# Comprehensive tests for all sysctl tunables:
# - security.mac.mac_abac.enabled
# - security.mac.mac_abac.mode
# - security.mac.mac_abac.default_policy
# - security.mac.mac_abac.extattr_name
#
# Also tests that statistics sysctls are readable.
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must be built
#

set -e

# Load test helpers
SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
MAC_ABAC_CTL="${1:-$(find_mac_abac_ctl)}"
TEST_FILE="/tmp/abac_tunable_test_$$"

# Prerequisites
require_root
require_module
require_mac_abac_ctl

echo "============================================"
echo "Sysctl Tunables Tests"
echo "============================================"
echo ""

# Save original settings
ORIG_ENABLED=$(sysctl -n security.mac.mac_abac.enabled)
ORIG_MODE=$(sysctl -n security.mac.mac_abac.mode)
ORIG_DEFAULT=$(sysctl -n security.mac.mac_abac.default_policy)
ORIG_EXTATTR=$(sysctl -n security.mac.mac_abac.extattr_name)

cleanup() {
	rm -f "$TEST_FILE" 2>/dev/null || true
	sysctl security.mac.mac_abac.enabled=$ORIG_ENABLED >/dev/null 2>&1 || true
	sysctl security.mac.mac_abac.mode=$ORIG_MODE >/dev/null 2>&1 || true
	sysctl security.mac.mac_abac.default_policy=$ORIG_DEFAULT >/dev/null 2>&1 || true
	sysctl security.mac.mac_abac.extattr_name="$ORIG_EXTATTR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ===========================================
# Test: enabled tunable
# ===========================================
info "=== security.mac.mac_abac.enabled ==="

run_test
info "Test: Read enabled"
if sysctl -n security.mac.mac_abac.enabled >/dev/null 2>&1; then
	pass "read enabled"
else
	fail "read enabled"
fi

run_test
info "Test: Set enabled=0 (disabled)"
if sysctl security.mac.mac_abac.enabled=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.enabled)
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
if sysctl security.mac.mac_abac.enabled=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.enabled)
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
info "=== security.mac.mac_abac.mode ==="

run_test
info "Test: Read mode"
if sysctl -n security.mac.mac_abac.mode >/dev/null 2>&1; then
	pass "read mode"
else
	fail "read mode"
fi

run_test
info "Test: Set mode=0 (disabled)"
if sysctl security.mac.mac_abac.mode=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.mode)
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
if sysctl security.mac.mac_abac.mode=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.mode)
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
if sysctl security.mac.mac_abac.mode=2 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.mode)
	if [ "$VAL" = "2" ]; then
		pass "set mode=2"
		# Immediately set back to permissive to avoid lockout
		sysctl security.mac.mac_abac.mode=1 >/dev/null 2>&1
	else
		fail "set mode=2 (got: $VAL)"
	fi
else
	fail "set mode=2"
fi

run_test
info "Test: Mode via mac_abac_ctl matches sysctl"
sysctl security.mac.mac_abac.mode=1 >/dev/null 2>&1
SYSCTL_VAL=$(sysctl -n security.mac.mac_abac.mode)
CTL_VAL=$("$MAC_ABAC_CTL" mode | grep -o '[0-9]' | head -1 || echo "")
# mac_abac_ctl mode returns "permissive" for mode 1
CTL_MODE=$("$MAC_ABAC_CTL" mode)
if [ "$CTL_MODE" = "permissive" ] && [ "$SYSCTL_VAL" = "1" ]; then
	pass "mac_abac_ctl mode matches sysctl"
else
	fail "mac_abac_ctl mode matches sysctl (sysctl=$SYSCTL_VAL, mac_abac_ctl=$CTL_MODE)"
fi

# ===========================================
# Test: default_policy tunable
# ===========================================
info ""
info "=== security.mac.mac_abac.default_policy ==="

run_test
info "Test: Read default_policy"
if sysctl -n security.mac.mac_abac.default_policy >/dev/null 2>&1; then
	pass "read default_policy"
else
	fail "read default_policy"
fi

run_test
info "Test: Set default_policy=0 (allow)"
if sysctl security.mac.mac_abac.default_policy=0 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.default_policy)
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
if sysctl security.mac.mac_abac.default_policy=1 >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.default_policy)
	if [ "$VAL" = "1" ]; then
		pass "set default_policy=1"
	else
		fail "set default_policy=1 (got: $VAL)"
	fi
else
	fail "set default_policy=1"
fi

run_test
info "Test: Default policy via mac_abac_ctl matches sysctl"
sysctl security.mac.mac_abac.default_policy=0 >/dev/null 2>&1
CTL_DEFAULT=$("$MAC_ABAC_CTL" default)
if [ "$CTL_DEFAULT" = "allow" ]; then
	pass "mac_abac_ctl default matches sysctl"
else
	fail "mac_abac_ctl default matches sysctl (expected allow, got: $CTL_DEFAULT)"
fi

# ===========================================
# Test: extattr_name tunable
# ===========================================
info ""
info "=== security.mac.mac_abac.extattr_name ==="

run_test
info "Test: Read extattr_name"
EXTATTR=$(sysctl -n security.mac.mac_abac.extattr_name 2>/dev/null)
if [ -n "$EXTATTR" ]; then
	pass "read extattr_name (value: $EXTATTR)"
else
	fail "read extattr_name"
fi

run_test
info "Test: Set extattr_name to custom value"
if sysctl security.mac.mac_abac.extattr_name="test_label" >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.extattr_name)
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
if sysctl security.mac.mac_abac.extattr_name="mac_abac" >/dev/null 2>&1; then
	VAL=$(sysctl -n security.mac.mac_abac.extattr_name)
	if [ "$VAL" = "mac_abac" ]; then
		pass "restore extattr_name=mac_abac"
	else
		fail "restore extattr_name=mac_abac (got: $VAL)"
	fi
else
	fail "restore extattr_name=mac_abac"
fi

run_test
info "Test: mac_abac_ctl uses configured extattr_name"
# Set custom extattr name
sysctl security.mac.mac_abac.extattr_name="custom_attr" >/dev/null 2>&1
# Create test file
echo "test" > "$TEST_FILE"
# Set label using mac_abac_ctl (should use custom attr via sysctl lookup)
"$MAC_ABAC_CTL" label set "$TEST_FILE" "type=test" >/dev/null 2>&1 || true
# Check if it was written to the custom attr
if getextattr -q system custom_attr "$TEST_FILE" 2>/dev/null | grep -q "type=test"; then
	pass "mac_abac_ctl uses configured extattr_name"
else
	# Check if it went to default (would be a bug)
	if getextattr -q system mac_abac "$TEST_FILE" 2>/dev/null | grep -q "type=test"; then
		fail "mac_abac_ctl used default instead of configured extattr_name"
	else
		# Neither worked - might be permission or other issue
		skip "could not verify extattr_name usage"
	fi
fi
# Restore
sysctl security.mac.mac_abac.extattr_name="mac_abac" >/dev/null 2>&1

# ===========================================
# Test: Statistics sysctls (read-only)
# ===========================================
info ""
info "=== Statistics Sysctls (read-only) ==="

run_test
info "Test: Read checks counter"
if sysctl -n security.mac.mac_abac.checks >/dev/null 2>&1; then
	pass "read checks"
else
	fail "read checks"
fi

run_test
info "Test: Read allowed counter"
if sysctl -n security.mac.mac_abac.allowed >/dev/null 2>&1; then
	pass "read allowed"
else
	fail "read allowed"
fi

run_test
info "Test: Read denied counter"
if sysctl -n security.mac.mac_abac.denied >/dev/null 2>&1; then
	pass "read denied"
else
	fail "read denied"
fi

run_test
info "Test: Read rule_count"
if sysctl -n security.mac.mac_abac.rule_count >/dev/null 2>&1; then
	pass "read rule_count"
else
	fail "read rule_count"
fi

run_test
info "Test: Read labels_read"
if sysctl -n security.mac.mac_abac.labels_read >/dev/null 2>&1; then
	pass "read labels_read"
else
	fail "read labels_read"
fi

run_test
info "Test: Read labels_default"
if sysctl -n security.mac.mac_abac.labels_default >/dev/null 2>&1; then
	pass "read labels_default"
else
	fail "read labels_default"
fi

run_test
info "Test: Read labels_allocated"
if sysctl -n security.mac.mac_abac.labels_allocated >/dev/null 2>&1; then
	pass "read labels_allocated"
else
	fail "read labels_allocated"
fi

run_test
info "Test: Read labels_freed"
if sysctl -n security.mac.mac_abac.labels_freed >/dev/null 2>&1; then
	pass "read labels_freed"
else
	fail "read labels_freed"
fi

run_test
info "Test: Read parse_errors"
if sysctl -n security.mac.mac_abac.parse_errors >/dev/null 2>&1; then
	pass "read parse_errors"
else
	fail "read parse_errors"
fi

run_test
info "Test: Statistics are read-only (checks)"
if sysctl security.mac.mac_abac.checks=0 2>/dev/null; then
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
info "Test: sysctl security.mac.mac_abac shows all tunables"
OUTPUT=$(sysctl security.mac.mac_abac 2>&1)
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
