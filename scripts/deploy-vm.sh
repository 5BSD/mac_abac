#!/bin/sh
#
# Deploy vLabelMACF to bhyve test VM
#
# Usage: ./deploy-vm.sh <vm-ip>
#
# This script:
# 1. Builds the kernel module and tools
# 2. Copies mac_vlabel.ko to /boot/modules
# 3. Copies vlabelctl to /usr/local/sbin
# 4. Copies tests to /root/vlabel-tests
#
# Note: Module requires VM reboot to load.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VM_USER="root"

# Require VM IP as argument
if [ -z "$1" ]; then
    echo "Usage: $0 <bhyve-vm-ip>"
    echo "Example: $0 192.168.7.134"
    exit 1
fi
VM="$1"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info() {
    printf "${GREEN}==>${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}WARNING:${NC} %s\n" "$1"
}

error() {
    printf "${RED}ERROR:${NC} %s\n" "$1"
    exit 1
}

# Check VM is reachable
info "Checking VM connectivity ($VM)..."
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ${VM_USER}@${VM} "true" 2>/dev/null; then
    error "Cannot connect to ${VM_USER}@${VM}. Is the VM running?"
fi

# Build kernel module
info "Building kernel module..."
(cd "$PROJECT_DIR/kernel" && make clean && make SYSDIR=/usr/src/sys) || error "Kernel module build failed"

if [ ! -f "$PROJECT_DIR/kernel/mac_vlabel.ko" ]; then
    error "Kernel module not found after build"
fi

# Build tools
info "Building tools..."
(cd "$PROJECT_DIR/tools" && make clean && make) || error "Tools build failed"

if [ ! -f "$PROJECT_DIR/tools/vlabelctl" ]; then
    error "vlabelctl not found after build"
fi

# Deploy kernel module to /boot/modules (first in search path)
info "Deploying kernel module..."
scp -q "$PROJECT_DIR/kernel/mac_vlabel.ko" ${VM_USER}@${VM}:/boot/modules/
ssh ${VM_USER}@${VM} "chmod 555 /boot/modules/mac_vlabel.ko"

# Deploy vlabelctl
info "Deploying vlabelctl..."
scp -q "$PROJECT_DIR/tools/vlabelctl" ${VM_USER}@${VM}:/usr/local/sbin/
ssh ${VM_USER}@${VM} "chmod 755 /usr/local/sbin/vlabelctl"

# Deploy tests
info "Deploying tests..."
ssh ${VM_USER}@${VM} "mkdir -p /root/vlabel-tests/lib"
scp -q "$PROJECT_DIR/tests/lib/test_helpers.sh" ${VM_USER}@${VM}:/root/vlabel-tests/lib/
scp -q "$PROJECT_DIR/tests/"*.sh ${VM_USER}@${VM}:/root/vlabel-tests/
ssh ${VM_USER}@${VM} "chmod +x /root/vlabel-tests/*.sh"

# Deploy test fixtures if they exist
if [ -d "$PROJECT_DIR/tests/fixtures" ]; then
    scp -qr "$PROJECT_DIR/tests/fixtures" ${VM_USER}@${VM}:/root/vlabel-tests/
fi

# Get file hashes from remote
info "Verifying deployment..."
KO_HASH=$(ssh ${VM_USER}@${VM} "sha256 -q /boot/modules/mac_vlabel.ko")
CTL_HASH=$(ssh ${VM_USER}@${VM} "sha256 -q /usr/local/sbin/vlabelctl")

echo ""
info "Deployment complete to ${VM}"
echo ""
echo "Source:      kernel/mac_vlabel.ko"
echo "Destination: /boot/modules/mac_vlabel.ko"
echo "Hash:        ${KO_HASH}"
echo ""
echo "Source:      tools/vlabelctl"
echo "Destination: /usr/local/sbin/vlabelctl"
echo "Hash:        ${CTL_HASH}"
echo ""
echo "Source:      tests/"
echo "Destination: /root/vlabel-tests/"
echo ""
echo "Reboot VM to load the new module."
