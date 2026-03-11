#!/bin/sh
#
# setup-vm.sh - Set up a bhyve VM for ABAC kernel module testing
#
# This script automates the creation of a FreeBSD test VM using vm-bhyve.
# Always test kernel modules in a VM to avoid crashing your host system!
#
# Usage:
#   sudo ./setup-vm.sh [vm-name]
#
# Prerequisites:
#   - FreeBSD 15.0+ host
#   - ZFS pool available
#   - Root privileges
#

set -e

# Configuration
VM_NAME="${1:-abac-test}"
VM_SIZE="20G"
VM_MEM="2G"
VM_CPUS="2"
ZFS_POOL="zroot"
ISO_URL="https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-amd64-disc1.iso"
ISO_NAME="FreeBSD-15.0-RELEASE-amd64-disc1.iso"
SWITCH_NAME="public"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { printf "${BLUE}==>${NC} %s\n" "$1"; }
success() { printf "${GREEN}==>${NC} %s\n" "$1"; }
warn() { printf "${YELLOW}WARNING:${NC} %s\n" "$1"; }
error() { printf "${RED}ERROR:${NC} %s\n" "$1"; exit 1; }

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (sudo)"
fi

echo ""
echo "=============================================="
echo "  ABAC Test VM Setup Script"
echo "=============================================="
echo ""
echo "This script will create a bhyve VM for testing"
echo "the ABAC kernel module safely."
echo ""
echo "Configuration:"
echo "  VM Name:    $VM_NAME"
echo "  Disk Size:  $VM_SIZE"
echo "  Memory:     $VM_MEM"
echo "  CPUs:       $VM_CPUS"
echo "  ZFS Pool:   $ZFS_POOL"
echo ""

# Step 1: Check/Install dependencies
info "Checking dependencies..."

if ! pkg info vm-bhyve >/dev/null 2>&1; then
    info "Installing vm-bhyve..."
    pkg install -y vm-bhyve grub2-bhyve
fi
success "vm-bhyve installed"

# Step 2: Load kernel modules
info "Loading kernel modules..."

if ! kldstat -q -m vmm 2>/dev/null; then
    kldload vmm || error "Failed to load vmm module"
fi

if ! kldstat -q -m nmdm 2>/dev/null; then
    kldload nmdm || error "Failed to load nmdm module"
fi
success "Kernel modules loaded (vmm, nmdm)"

# Step 3: Create ZFS dataset if needed
info "Setting up VM storage..."

if ! zfs list ${ZFS_POOL}/vm >/dev/null 2>&1; then
    zfs create ${ZFS_POOL}/vm
    success "Created ${ZFS_POOL}/vm dataset"
else
    success "Using existing ${ZFS_POOL}/vm dataset"
fi

# Step 4: Configure vm-bhyve
info "Configuring vm-bhyve..."

sysrc vm_enable="YES" >/dev/null
sysrc vm_dir="zfs:${ZFS_POOL}/vm" >/dev/null

# Initialize if needed
if [ ! -d "$(zfs get -H -o value mountpoint ${ZFS_POOL}/vm)/.config" ]; then
    vm init
fi
success "vm-bhyve configured"

# Step 5: Create network switch if needed
info "Setting up network..."

if ! vm switch list | grep -q "^${SWITCH_NAME}"; then
    vm switch create ${SWITCH_NAME}

    # Try to find the main network interface
    MAIN_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    if [ -n "$MAIN_IF" ]; then
        vm switch add ${SWITCH_NAME} ${MAIN_IF}
        success "Created switch '${SWITCH_NAME}' attached to ${MAIN_IF}"
    else
        warn "Could not detect main interface. Manually run:"
        echo "    vm switch add ${SWITCH_NAME} <your-interface>"
    fi
else
    success "Using existing switch '${SWITCH_NAME}'"
fi

# Step 6: Download ISO if needed
info "Checking for FreeBSD ISO..."

ISO_DIR="$(zfs get -H -o value mountpoint ${ZFS_POOL}/vm)/.iso"
if [ ! -f "${ISO_DIR}/${ISO_NAME}" ]; then
    info "Downloading FreeBSD 15.0 ISO (this may take a while)..."
    vm iso ${ISO_URL}
    success "ISO downloaded"
else
    success "ISO already present"
fi

# Step 7: Create VM if needed
info "Setting up VM '${VM_NAME}'..."

if vm list | grep -q "^${VM_NAME}"; then
    warn "VM '${VM_NAME}' already exists"
    echo ""
    echo "To reinstall, run:"
    echo "    sudo vm destroy ${VM_NAME}"
    echo "    sudo ./setup-vm.sh ${VM_NAME}"
    echo ""
else
    # Use default template (creates disk image, not zvol)
    vm create -s ${VM_SIZE} ${VM_NAME}
    success "Created VM '${VM_NAME}'"
fi

# Step 8: Print next steps
echo ""
echo "=============================================="
success "VM setup complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Install FreeBSD in the VM:"
echo "   ${BLUE}sudo vm install ${VM_NAME} ${ISO_NAME}${NC}"
echo ""
echo "   During installation:"
echo "   - Set hostname to '${VM_NAME}'"
echo "   - Enable SSH and set root password"
echo "   - Configure network with DHCP"
echo ""
echo "2. After installation, start the VM:"
echo "   ${BLUE}sudo vm start ${VM_NAME}${NC}"
echo ""
echo "3. Connect to console:"
echo "   ${BLUE}sudo vm console ${VM_NAME}${NC}"
echo "   (Ctrl+B d to detach)"
echo ""
echo "4. Or SSH in (get IP from console or DHCP leases):"
echo "   ${BLUE}ssh root@<vm-ip>${NC}"
echo ""
echo "5. Copy and test the kernel module:"
echo "   ${BLUE}scp kernel/mac_abac.ko root@<vm-ip>:/root/${NC}"
echo "   ${BLUE}ssh root@<vm-ip> 'kldload /root/mac_abac.ko'${NC}"
echo ""
echo "For more commands:"
echo "   vm list              - List all VMs"
echo "   vm info ${VM_NAME}   - Show VM details"
echo "   vm stop ${VM_NAME}   - Stop the VM"
echo "   vm destroy ${VM_NAME} - Delete the VM"
echo ""
