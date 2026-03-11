#!/bin/sh
#
# Run all ABAC tests
#
# Usage:
#   ./run_all.sh [-q] [module_path] [mac_abac_ctl_path]
#
# Options:
#   -q    Quiet mode - only show failures and summary
#

set -e

SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR"

# Parse options
QUIET_MODE=0
while getopts "q" opt; do
    case $opt in
        q) QUIET_MODE=1 ;;
        *) echo "Usage: $0 [-q] [module_path] [mac_abac_ctl_path]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

# Export for test_helpers.sh
export ABAC_QUIET="$QUIET_MODE"

# Default paths - check VM locations first, then local build
if [ -n "$1" ]; then
    MODULE_PATH="$1"
elif [ -f "/root/mac_abac.ko" ]; then
    MODULE_PATH="/root/mac_abac.ko"
else
    MODULE_PATH="../kernel/mac_abac.ko"
fi

if [ -n "$2" ]; then
    MAC_ABAC_CTL="$2"
elif [ -x "/usr/local/bin/mac_abac_ctl" ]; then
    MAC_ABAC_CTL="/usr/local/bin/mac_abac_ctl"
else
    MAC_ABAC_CTL="../tools/mac_abac_ctl"
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

if [ "$QUIET_MODE" != "1" ]; then
    echo ""
    printf "${BLUE}============================================${NC}\n"
    printf "${BLUE}     ABAC MAC Module Test Suite${NC}\n"
    printf "${BLUE}============================================${NC}\n"
    echo ""
fi

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

run_test_script() {
    NAME="$1"
    SCRIPT="$2"
    shift 2

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    if [ "$QUIET_MODE" != "1" ]; then
        echo ""
        printf "${YELLOW}>>> Running: $NAME${NC}\n"
        echo ""
    fi

    if [ -x "$SCRIPT" ]; then
        if "$SCRIPT" "$@"; then
            PASSED_TESTS=$((PASSED_TESTS + 1))
            if [ "$QUIET_MODE" != "1" ]; then
                printf "${GREEN}<<< $NAME: PASSED${NC}\n"
            fi
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
if [ "$QUIET_MODE" != "1" ]; then
    echo ""
    printf "${YELLOW}>>> Skipping: Module Load/Unload (unloading not supported)${NC}\n"
    echo "    Module can load after boot, but cannot unload; reboot to update"
fi

# Ensure module is loaded
if ! kldstat -q -m mac_abac 2>/dev/null; then
    echo "Module not loaded, loading..."
    kldload "$MODULE_PATH"
fi

run_test_script "mac_abac_ctl Commands" ./02_mac_abac_ctl.sh "$MAC_ABAC_CTL"
run_test_script "Sysctl Tunables" ./03_tunables.sh "$MAC_ABAC_CTL"
run_test_script "Label Format" ./03_label_format.sh "$MAC_ABAC_CTL"
run_test_script "Default Policy" ./04_default_policy.sh "$MAC_ABAC_CTL"
run_test_script "Debug/Signal/Sched" ./05_debug_check.sh "$MAC_ABAC_CTL"
run_test_script "Rule Validation" ./06_rule_validate.sh "$MAC_ABAC_CTL"
run_test_script "Rule Load" ./07_rule_load.sh "$MAC_ABAC_CTL"
run_test_script "mac_syscall API" ./09_syscall_api.sh "$MAC_ABAC_CTL"
run_test_script "Limits" ./10_limits.sh "$MAC_ABAC_CTL"
run_test_script "Process Enforcement" ./12_process_enforcement.sh "$MAC_ABAC_CTL"
run_test_script "Label Transitions" ./13_transitions.sh "$MAC_ABAC_CTL"
run_test_script "Context Debug" ./14_context_debug.sh "$MAC_ABAC_CTL"
run_test_script "Context Constraints" ./15_context_constraints.sh "$MAC_ABAC_CTL"
run_test_script "Policy Formats" ./16_formats.sh "$MAC_ABAC_CTL"
run_test_script "Pattern Negation" ./17_negation.sh "$MAC_ABAC_CTL"
run_test_script "File Operations" ./12_file_ops.sh "$MAC_ABAC_CTL"
run_test_script "Label Protection" ./18_label_protection.sh "$MAC_ABAC_CTL"
run_test_script "Socket Operations" ./19_socket.sh "$MAC_ABAC_CTL"
run_test_script "Pipe Operations" ./20_pipe.sh "$MAC_ABAC_CTL"
run_test_script "POSIX Shared Memory" ./21_posixshm.sh "$MAC_ABAC_CTL"
run_test_script "Directory & Metadata" ./22_directory.sh "$MAC_ABAC_CTL"
run_test_script "System Operations" ./23_system.sh "$MAC_ABAC_CTL"
run_test_script "Vnode Extra Hooks" ./24_vnode_extra.sh "$MAC_ABAC_CTL"
run_test_script "Kenv Operations" ./25_kenv.sh "$MAC_ABAC_CTL"
run_test_script "Atomic Setlabel" ./26_atomic_setlabel.sh "$MAC_ABAC_CTL"
run_test_script "Recursive Labeling" ./27_recursive_label.sh "$MAC_ABAC_CTL"

# DTrace test - only run if dtrace is available
if which dtrace >/dev/null 2>&1; then
    run_test_script "DTrace Probes" ./11_dtrace.sh "$MAC_ABAC_CTL"
elif [ "$QUIET_MODE" != "1" ]; then
    echo ""
    printf "${YELLOW}>>> Skipping: DTrace Probes (dtrace not available)${NC}\n"
fi

# Enforcement test - requires labeled binaries set up before module load
# Run scripts/deploy-test.sh to set up the test environment properly
run_test_script "Enforcement" ./08_enforcement.sh "$MAC_ABAC_CTL"

# Sets test
if [ -x ./28_sets.sh ]; then
    run_test_script "Label Sets" ./28_sets.sh "$MAC_ABAC_CTL"
fi

# SysV IPC tests
run_test_script "SysV Message Queues" ./31_sysv_msgq.sh "$MAC_ABAC_CTL"
run_test_script "SysV Semaphores" ./32_sysv_sem.sh "$MAC_ABAC_CTL"

# Sanity and stress tests
run_test_script "Sanity Checks" ./29_sanity.sh "$MAC_ABAC_CTL"
run_test_script "Stress Tests" ./30_stress.sh "$MAC_ABAC_CTL"

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
