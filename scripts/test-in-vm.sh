#!/bin/sh
#
# test-in-vm.sh - Build, copy, and test vLabel module in VM
#
# This script automates the build-copy-test cycle for kernel development.
#
# Usage:
#   ./test-in-vm.sh <vm-ip> [test-script]
#
# Examples:
#   ./test-in-vm.sh 192.168.1.100
#   ./test-in-vm.sh 192.168.1.100 tests/01_load_unload.sh
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
KERNEL_DIR="${PROJECT_DIR}/kernel"
TESTS_DIR="${PROJECT_DIR}/tests"
MODULE_NAME="mac_vlabel.ko"
REMOTE_PATH="/root"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { printf "${BLUE}==>${NC} %s\n" "$1"; }
success() { printf "${GREEN}==>${NC} %s\n" "$1"; }
error() { printf "${RED}ERROR:${NC} %s\n" "$1"; exit 1; }

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <vm-ip> [test-script]"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100"
    echo "  $0 192.168.1.100 tests/01_load_unload.sh"
    exit 1
fi

VM_IP="$1"
TEST_SCRIPT="$2"

echo ""
echo "=============================================="
echo "  vLabel VM Test Script"
echo "=============================================="
echo ""

# Step 1: Build the module
info "Building kernel module..."
cd "${KERNEL_DIR}"

if [ ! -f /usr/src/sys/kern/vnode_if.src ]; then
    error "FreeBSD source not found at /usr/src. Please install it first."
fi

make clean >/dev/null 2>&1 || true
if ! make SYSDIR=/usr/src/sys 2>&1; then
    error "Build failed"
fi
success "Module built successfully"

# Step 2: Check VM connectivity
info "Checking VM connectivity..."
if ! ping -c 1 -t 2 "${VM_IP}" >/dev/null 2>&1; then
    error "Cannot reach VM at ${VM_IP}. Is it running?"
fi
success "VM is reachable"

# Step 3: Unload existing module if loaded
info "Checking for existing module in VM..."
ssh -o ConnectTimeout=5 "root@${VM_IP}" "kldstat -q -m mac_vlabel && kldunload mac_vlabel || true" 2>/dev/null
success "VM ready for new module"

# Step 4: Copy module to VM
info "Copying module to VM..."
scp -q "${KERNEL_DIR}/${MODULE_NAME}" "root@${VM_IP}:${REMOTE_PATH}/"
success "Module copied to ${VM_IP}:${REMOTE_PATH}/${MODULE_NAME}"

# Step 5: Copy and run test script if specified
if [ -n "$TEST_SCRIPT" ]; then
    if [ -f "${PROJECT_DIR}/${TEST_SCRIPT}" ]; then
        TEST_BASENAME="$(basename "$TEST_SCRIPT")"
        info "Copying test script..."
        scp -q "${PROJECT_DIR}/${TEST_SCRIPT}" "root@${VM_IP}:${REMOTE_PATH}/"

        info "Running test: ${TEST_BASENAME}"
        echo "----------------------------------------------"
        ssh "root@${VM_IP}" "cd ${REMOTE_PATH} && sh ./${TEST_BASENAME} ./${MODULE_NAME}"
        echo "----------------------------------------------"
    else
        error "Test script not found: ${TEST_SCRIPT}"
    fi
else
    # Default: just load and show sysctl
    info "Loading module in VM..."
    echo "----------------------------------------------"
    ssh "root@${VM_IP}" "
        echo 'Loading module...'
        kldload ${REMOTE_PATH}/${MODULE_NAME}
        echo ''
        echo 'Module loaded. sysctl values:'
        sysctl security.mac.vlabel
        echo ''
        echo 'To unload: kldunload mac_vlabel'
    "
    echo "----------------------------------------------"
fi

echo ""
success "Done!"
echo ""
