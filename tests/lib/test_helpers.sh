#!/bin/sh
#
# Shared test helper functions for ABAC test suite
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Quiet mode - set ABAC_QUIET=1 to only show failures and summary
ABAC_QUIET="${ABAC_QUIET:-0}"

# Pass a test
pass() {
	TESTS_PASSED=$((TESTS_PASSED + 1))
	if [ "$ABAC_QUIET" != "1" ]; then
		printf "${GREEN}PASS${NC}: %s\n" "$1"
	fi
}

# Fail a test
fail() {
	printf "${RED}FAIL${NC}: %s\n" "$1"
	TESTS_FAILED=$((TESTS_FAILED + 1))
}

# Skip a test
skip() {
	TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
	if [ "$ABAC_QUIET" != "1" ]; then
		printf "${YELLOW}SKIP${NC}: %s\n" "$1"
	fi
}

# Info message
info() {
	if [ "$ABAC_QUIET" != "1" ]; then
		printf "INFO: %s\n" "$1"
	fi
}

# Warning message
warn() {
	printf "${YELLOW}WARN${NC}: %s\n" "$1"
}

# Increment test counter
run_test() {
	TESTS_RUN=$((TESTS_RUN + 1))
}

# Assert two values are equal
assert_equals() {
	local expected="$1"
	local actual="$2"
	local message="$3"

	run_test
	if [ "$expected" = "$actual" ]; then
		pass "$message"
		return 0
	else
		fail "$message (expected '$expected', got '$actual')"
		return 1
	fi
}

# Assert output contains a string
assert_contains() {
	local haystack="$1"
	local needle="$2"
	local message="$3"

	run_test
	if echo "$haystack" | grep -q "$needle"; then
		pass "$message"
		return 0
	else
		fail "$message (expected to contain '$needle')"
		return 1
	fi
}

# Assert output does not contain a string
assert_not_contains() {
	local haystack="$1"
	local needle="$2"
	local message="$3"

	run_test
	if echo "$haystack" | grep -q "$needle"; then
		fail "$message (should not contain '$needle')"
		return 1
	else
		pass "$message"
		return 0
	fi
}

# Assert command exits with specific code
assert_exit_code() {
	local cmd="$1"
	local expected="$2"
	local message="$3"

	run_test
	eval "$cmd" >/dev/null 2>&1
	local actual=$?
	if [ "$actual" -eq "$expected" ]; then
		pass "$message"
		return 0
	else
		fail "$message (expected exit $expected, got $actual)"
		return 1
	fi
}

# Assert command succeeds (exit 0)
assert_success() {
	local cmd="$1"
	local message="$2"

	assert_exit_code "$cmd" 0 "$message"
}

# Assert command fails (exit non-zero)
assert_failure() {
	local cmd="$1"
	local message="$2"

	run_test
	eval "$cmd" >/dev/null 2>&1
	local actual=$?
	if [ "$actual" -ne 0 ]; then
		pass "$message"
		return 0
	else
		fail "$message (expected failure, got success)"
		return 1
	fi
}

# Check if running as root
require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "This test must be run as root"
		exit 1
	fi
}

# Check if module is loaded
require_module() {
	if ! kldstat -q -m mac_abac 2>/dev/null; then
		echo "Module mac_abac not loaded"
		exit 1
	fi
}

# Find mac_abac_ctl - check installed locations first, then local build
find_mac_abac_ctl() {
	if [ -n "$MAC_ABAC_CTL" ] && [ -x "$MAC_ABAC_CTL" ]; then
		echo "$MAC_ABAC_CTL"
	elif [ -x "/usr/local/sbin/mac_abac_ctl" ]; then
		echo "/usr/local/sbin/mac_abac_ctl"
	elif [ -x "/usr/local/bin/mac_abac_ctl" ]; then
		echo "/usr/local/bin/mac_abac_ctl"
	elif [ -x "../tools/mac_abac_ctl" ]; then
		echo "../tools/mac_abac_ctl"
	else
		echo "mac_abac_ctl"
	fi
}

# Check if mac_abac_ctl exists
require_mac_abac_ctl() {
	local mac_abac_ctl
	mac_abac_ctl=$(find_mac_abac_ctl)
	if [ ! -x "$mac_abac_ctl" ]; then
		echo "mac_abac_ctl not found or not executable: $mac_abac_ctl"
		exit 1
	fi
}

# Print test summary
summary() {
	echo ""
	echo "============================================"
	echo "Test Summary"
	echo "============================================"
	echo "Tests run:    $TESTS_RUN"
	printf "${GREEN}Passed:       $TESTS_PASSED${NC}\n"
	if [ $TESTS_FAILED -gt 0 ]; then
		printf "${RED}Failed:       $TESTS_FAILED${NC}\n"
	else
		echo "Failed:       $TESTS_FAILED"
	fi
	if [ $TESTS_SKIPPED -gt 0 ]; then
		printf "${YELLOW}Skipped:      $TESTS_SKIPPED${NC}\n"
	fi
	echo ""

	if [ $TESTS_FAILED -eq 0 ]; then
		printf "${GREEN}ALL TESTS PASSED${NC}\n"
		return 0
	else
		printf "${RED}SOME TESTS FAILED${NC}\n"
		return 1
	fi
}

# Cleanup function placeholder - override in test scripts
cleanup() {
	:
}

# Set trap for cleanup on exit
trap cleanup EXIT
