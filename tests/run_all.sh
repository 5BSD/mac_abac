#!/bin/sh
#
# Run all vLabel tests
#
# Usage:
#   ./run_all.sh [module_path] [vlabelctl_path]
#

set -e

SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR"

# Default paths - check VM locations first, then local build
if [ -n "$1" ]; then
    MODULE_PATH="$1"
elif [ -f "/root/mac_vlabel.ko" ]; then
    MODULE_PATH="/root/mac_vlabel.ko"
else
    MODULE_PATH="../kernel/mac_vlabel.ko"
fi

if [ -n "$2" ]; then
    VLABELCTL="$2"
elif [ -x "/usr/local/bin/vlabelctl" ]; then
    VLABELCTL="/usr/local/bin/vlabelctl"
else
    VLABELCTL="../tools/vlabelctl"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

echo ""
printf "${BLUE}============================================${NC}\n"
printf "${BLUE}     vLabel MAC Module Test Suite${NC}\n"
printf "${BLUE}============================================${NC}\n"
echo ""

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test_script() {
    NAME="$1"
    SCRIPT="$2"
    shift 2

    echo ""
    printf "${YELLOW}>>> Running: $NAME${NC}\n"
    echo ""

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ -x "$SCRIPT" ]; then
        if "$SCRIPT" "$@"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            printf "${GREEN}<<< $NAME: PASSED${NC}\n"
        else
            FAILED_TESTS=$((FAILED_TESTS + 1))
            printf "${RED}<<< $NAME: FAILED${NC}\n"
        fi
    else
        printf "${RED}<<< $NAME: SCRIPT NOT EXECUTABLE${NC}\n"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Make test scripts executable
chmod +x *.sh 2>/dev/null || true

# NOTE: Module Load/Unload test (01_load_unload.sh) is SKIPPED because:
# - The module does not set UNLOADOK flag, so unloading is blocked by kernel
# - Unloading would leave orphaned labels attached to kernel objects
# - Reloading after unload corrupts kernel state (UMA zone conflicts)
#
# For development, reboot between module updates instead of unload/reload.
echo ""
printf "${YELLOW}>>> Skipping: Module Load/Unload (unloading not supported)${NC}\n"
echo "    Module can load after boot, but cannot unload; reboot to update"

# Ensure module is loaded
if ! kldstat -q -m mac_vlabel 2>/dev/null; then
    echo "Module not loaded, loading..."
    kldload "$MODULE_PATH"
fi

run_test_script "vlabelctl Commands" ./02_vlabelctl.sh "$VLABELCTL"
run_test_script "Label Format" ./03_label_format.sh "$VLABELCTL"
run_test_script "Default Policy" ./04_default_policy.sh "$VLABELCTL"
run_test_script "Debug/Signal/Sched" ./05_debug_check.sh "$VLABELCTL"
run_test_script "Rule Validation" ./06_rule_validate.sh "$VLABELCTL"
run_test_script "Rule Load" ./07_rule_load.sh "$VLABELCTL"
run_test_script "mac_syscall API" ./09_syscall_api.sh "$VLABELCTL"
run_test_script "Limits" ./10_limits.sh "$VLABELCTL"
run_test_script "Process Enforcement" ./12_process_enforcement.sh "$VLABELCTL"
run_test_script "Label Transitions" ./13_transitions.sh "$VLABELCTL"

# DTrace test - only run if dtrace is available
if which dtrace >/dev/null 2>&1; then
    run_test_script "DTrace Probes" ./11_dtrace.sh "$VLABELCTL"
else
    echo ""
    printf "${YELLOW}>>> Skipping: DTrace Probes (dtrace not available)${NC}\n"
fi

# NOTE: Enforcement test (08_enforcement.sh) is SKIPPED in the automated suite.
# It requires special conditions:
#   1. Test binaries must be labeled BEFORE module load
#   2. Module must not have been unloaded/reloaded (clears vnode labels)
#   3. Test binaries must not have been accessed since module load
#
# To run enforcement tests properly:
#   1. Reboot or fresh boot
#   2. Run: scripts/deploy-test.sh (sets up labeled binaries before module load)
#   3. Run: tests/08_enforcement.sh /usr/local/bin/vlabelctl
#
echo ""
printf "${YELLOW}>>> Skipping: Enforcement (requires fresh module load)${NC}\n"
echo "    Run manually after fresh boot with: ./08_enforcement.sh"

# Summary
echo ""
printf "${BLUE}============================================${NC}\n"
printf "${BLUE}           Final Test Summary${NC}\n"
printf "${BLUE}============================================${NC}\n"
echo ""
echo "Test scripts run: $TOTAL_TESTS"
printf "${GREEN}Passed: $PASSED_TESTS${NC}\n"
if [ $FAILED_TESTS -gt 0 ]; then
    printf "${RED}Failed: $FAILED_TESTS${NC}\n"
else
    echo "Failed: $FAILED_TESTS"
fi
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    printf "${GREEN}========================================${NC}\n"
    printf "${GREEN}    ALL TEST SUITES PASSED${NC}\n"
    printf "${GREEN}========================================${NC}\n"
    exit 0
else
    printf "${RED}========================================${NC}\n"
    printf "${RED}    SOME TEST SUITES FAILED${NC}\n"
    printf "${RED}========================================${NC}\n"
    exit 1
fi
