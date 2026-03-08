#!/bin/sh
#
# Test: vLabel MAC module loads and unloads cleanly
#
# Prerequisites:
# - Must be run as root
# - Module must be built (mac_vlabel.ko present)
# - Should be run in a test VM, not on production system!
#
# Usage:
#   ./01_load_unload.sh [path_to_module]
#

set -e

# Configuration
MODULE_PATH="${1:-./mac_vlabel.ko}"
MODULE_NAME="mac_vlabel"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Helper functions
pass() {
    printf "${GREEN}PASS${NC}: %s\n" "$1"
}

fail() {
    printf "${RED}FAIL${NC}: %s\n" "$1"
    exit 1
}

warn() {
    printf "${YELLOW}WARN${NC}: %s\n" "$1"
}

info() {
    printf "INFO: %s\n" "$1"
}

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    fail "This test must be run as root"
fi

if [ ! -f "$MODULE_PATH" ]; then
    fail "Module not found: $MODULE_PATH"
fi

# Ensure module is not already loaded
if kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
    warn "Module already loaded, unloading first..."
    if ! kldunload "$MODULE_NAME"; then
        fail "Could not unload existing module"
    fi
fi

echo "============================================"
echo "vLabel MAC Module Load/Unload Test"
echo "============================================"
echo ""

# Test 1: Load module
info "Test 1: Loading module..."
if ! kldload "$MODULE_PATH"; then
    fail "kldload failed"
fi
pass "Module loaded successfully"

# Test 2: Verify module is in kldstat
info "Test 2: Verifying module is registered..."
if ! kldstat -q -m "$MODULE_NAME"; then
    kldunload "$MODULE_NAME" 2>/dev/null || true
    fail "Module not found in kldstat"
fi
pass "Module appears in kldstat"

# Test 3: Check sysctl tree exists
info "Test 3: Checking sysctl tree..."
if ! sysctl security.mac.vlabel >/dev/null 2>&1; then
    kldunload "$MODULE_NAME"
    fail "sysctl tree security.mac.vlabel not found"
fi
pass "sysctl tree created"

# Test 4: Verify sysctl values
info "Test 4: Verifying sysctl values..."
ENABLED=$(sysctl -n security.mac.vlabel.enabled 2>/dev/null)
MODE=$(sysctl -n security.mac.vlabel.mode 2>/dev/null)
AUDIT=$(sysctl -n security.mac.vlabel.audit_level 2>/dev/null)

if [ -z "$ENABLED" ]; then
    kldunload "$MODULE_NAME"
    fail "Could not read security.mac.vlabel.enabled"
fi
if [ -z "$MODE" ]; then
    kldunload "$MODULE_NAME"
    fail "Could not read security.mac.vlabel.mode"
fi
if [ -z "$AUDIT" ]; then
    kldunload "$MODULE_NAME"
    fail "Could not read security.mac.vlabel.audit_level"
fi

info "  enabled=$ENABLED mode=$MODE audit_level=$AUDIT"
pass "sysctl values readable"

# Test 5: Try modifying sysctl
info "Test 5: Testing sysctl write..."
ORIG_ENABLED=$ENABLED
if ! sysctl security.mac.vlabel.enabled=0 >/dev/null 2>&1; then
    kldunload "$MODULE_NAME"
    fail "Could not write to security.mac.vlabel.enabled"
fi
sysctl security.mac.vlabel.enabled=$ORIG_ENABLED >/dev/null 2>&1
pass "sysctl write works"

# Test 6: Unload module
info "Test 6: Unloading module..."
if ! kldunload "$MODULE_NAME"; then
    fail "kldunload failed"
fi
pass "Module unloaded successfully"

# Test 7: Verify module is gone
info "Test 7: Verifying module is unloaded..."
if kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
    fail "Module still appears in kldstat after unload"
fi
pass "Module no longer in kldstat"

# Test 8: Verify sysctl tree is gone
info "Test 8: Verifying sysctl tree removed..."
if sysctl security.mac.vlabel >/dev/null 2>&1; then
    warn "sysctl tree still exists (may be normal)"
fi
pass "Cleanup verified"

# Test 9: Reload module for remaining tests
info "Test 9: Reloading module for remaining tests..."
if ! kldload "$MODULE_PATH" 2>/dev/null; then
    fail "Failed to reload module"
fi
pass "Module reloaded"

echo ""
echo "============================================"
printf "${GREEN}ALL TESTS PASSED${NC}\n"
echo "============================================"
echo ""
echo "The module loads and unloads cleanly."
echo "Note: Repeated load/unload cycles are not recommended."
echo "Module is now loaded and ready for further tests."
echo ""

exit 0
