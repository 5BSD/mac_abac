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

MODULE_PATH="${1:-../kernel/mac_vlabel.ko}"
VLABELCTL="${2:-../tools/vlabelctl}"

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

# Run tests in order
run_test_script "Module Load/Unload" ./01_load_unload.sh "$MODULE_PATH"

# Load module for remaining tests
if ! kldstat -q -m mac_vlabel 2>/dev/null; then
    echo "Loading module for remaining tests..."
    kldload "$MODULE_PATH"
fi

run_test_script "vlabelctl Commands" ./02_vlabelctl.sh "$VLABELCTL"
run_test_script "Label Format" ./03_label_format.sh "$VLABELCTL"
run_test_script "Default Policy" ./04_default_policy.sh "$VLABELCTL"
run_test_script "Debug/Signal/Sched" ./05_debug_check.sh "$VLABELCTL"
run_test_script "Rule Validation" ./06_rule_validate.sh "$VLABELCTL"
run_test_script "Rule Load" ./07_rule_load.sh "$VLABELCTL"

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
