#!/bin/sh
#
# install-swift-vm.sh - Install Swift runtime on VM
#
# Run this script from the host to install Swift on the VM.
#

VM_IP="192.168.7.134"

ssh root@${VM_IP} "
    ASSUME_ALWAYS_YES=yes pkg bootstrap
    pkg update
    pkg search swift | head -10
    echo ''
    echo 'Installing swift...'
    pkg install -y swift
    echo ''
    echo 'Verifying installation...'
    which swift || echo 'swift not in PATH'
    swift --version || echo 'swift --version failed'
"
