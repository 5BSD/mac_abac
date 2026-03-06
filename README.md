# vLabel - Label-Based MAC Policy for FreeBSD

vLabel is a Mandatory Access Control Framework (MACF) policy module for FreeBSD that provides fine-grained access control using security labels stored in extended attributes.

## Overview

vLabel allows administrators to:
- **Label filesystem objects** with key-value security attributes (e.g., `type=system,domain=daemon,level=high`)
- **Label processes** that inherit or transition labels on execution
- **Define access control rules** that allow or deny operations based on subject/object label matching
- **Assert process context** requirements (jail membership, capability mode, UID/GID)
- **Audit all policy decisions** for security monitoring

## Features

- **Persistent Labels**: Security labels stored in `system:vlabel` extended attributes survive reboots
- **Key-Value Format**: Flexible labeling with `type=`, `domain=`, `name=`, `level=` attributes
- **Rule-Based Policy**: First-match allow/deny rules with wildcard support
- **Context Assertions**: Rules can require specific process contexts (jail, capsicum, uid)
- **Enforcement Modes**: Enforcing, permissive (log-only), or disabled
- **Full Audit Trail**: Configurable logging of all policy decisions
- **Userland Tools**: `vlabeld` daemon and `vlabelctl` CLI for management

## Requirements

- FreeBSD 15.0 or later
- Kernel compiled with `options MAC`
- ZFS or UFS filesystem with extended attribute support
- Root privileges for module loading and label management

## Quick Start

### Building

```bash
# Clone the repository
git clone https://github.com/youruser/vLabelMACF.git
cd vLabelMACF

# Ensure FreeBSD source is available
# (needed for kernel module compilation)
sudo git clone --depth 1 -b releng/15.0 \
    https://github.com/freebsd/freebsd-src.git /usr/src

# Build the kernel module
cd kernel
make SYSDIR=/usr/src/sys

# The module is now at kernel/mac_vlabel.ko
```

### Testing (Use a VM!)

**WARNING**: Always test kernel modules in a VM first. A bug can crash your system.

```bash
# See scripts/setup-vm.sh for VM setup instructions
# Or manually:
sudo kldload ./mac_vlabel.ko
sysctl security.mac.vlabel
sudo kldunload mac_vlabel
```

### Basic Usage

```bash
# Load the module (starts in permissive mode)
sudo kldload mac_vlabel.ko

# Check status
sysctl security.mac.vlabel

# Label a file
sudo setextattr system vlabel "type=app,domain=web,name=httpd" /usr/local/sbin/httpd

# View a label
getextattr system vlabel /usr/local/sbin/httpd

# Switch to enforcing mode (careful!)
sudo sysctl security.mac.vlabel.mode=2
```

## Project Structure

```
vLabelMACF/
├── kernel/                 # Kernel module source
│   ├── mac_vlabel.c       # Main module with MACF entry points
│   ├── mac_vlabel.h       # Structures, constants, macros
│   └── Makefile           # Kernel module build
├── tests/                  # Test scripts
│   └── 01_load_unload.sh  # Basic module load/unload test
├── scripts/                # Setup and utility scripts
│   └── setup-vm.sh        # Test VM setup script
├── REQUIREMENTS.md         # Detailed requirements specification
└── README.md              # This file
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Space                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ vlabelctl   │  │  vlabeld    │  │  setextattr/        │  │
│  │ (CLI tool)  │  │  (daemon)   │  │  getextattr         │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│         └────────────────┼─────────────────────┘             │
│                          │ ioctl / extattr syscalls          │
├──────────────────────────┼───────────────────────────────────┤
│                     Kernel Space                             │
│                          │                                   │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │                  mac_vlabel.ko                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  │  │
│  │  │ Label Mgmt  │  │ Rule Engine │  │ Audit System  │  │  │
│  │  │ (extattr)   │  │ (matching)  │  │ (ring buffer) │  │  │
│  │  └─────────────┘  └─────────────┘  └───────────────┘  │  │
│  │                          │                             │  │
│  │         MACF Entry Points (50+ hooks)                  │  │
│  └──────────────────────────┼────────────────────────────┘  │
│                             │                                │
│  ┌──────────────────────────▼────────────────────────────┐  │
│  │              FreeBSD MAC Framework                     │  │
│  │         (vnode, credential, process hooks)             │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Label Format

Labels use a key-value pair format stored in the `system:vlabel` extended attribute:

```
type=<type>,domain=<domain>,name=<name>,level=<level>
```

### Reserved Keys

| Key | Description | Examples |
|-----|-------------|----------|
| `type` | Object/subject classification | `system`, `app`, `user`, `untrusted` |
| `domain` | Functional domain | `network`, `storage`, `daemon` |
| `name` | Specific identifier | `httpd`, `sshd`, `firefox` |
| `level` | Sensitivity/trust level | `high`, `medium`, `low` |

### Examples

```bash
# System daemon
type=system,domain=daemon,name=sshd,level=high

# User application
type=app,domain=network,name=firefox,level=low

# Untrusted download
type=untrusted,level=low
```

## Configuration

### sysctl Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `security.mac.vlabel.enabled` | 1 | Enable/disable the policy |
| `security.mac.vlabel.mode` | 1 | 0=disabled, 1=permissive, 2=enforcing |
| `security.mac.vlabel.audit_level` | 1 | 0=none, 1=denials, 2=all, 3=verbose |

### Enforcement Modes

- **Disabled (0)**: Module loaded but inactive
- **Permissive (1)**: Evaluates policy, logs decisions, but allows all access
- **Enforcing (2)**: Denies access when policy prohibits it

## Development

### Building with Debug Output

```bash
make SYSDIR=/usr/src/sys VLABEL_DEBUG=1
```

### Running Tests

```bash
# In a test VM as root:
cd /path/to/vLabelMACF/tests
./01_load_unload.sh ../kernel/mac_vlabel.ko
```

### Test VM Setup

**Always test kernel modules in a VM first!** A bug can crash your system.

#### Quick Setup (Manual)

```bash
# Install vm-bhyve
sudo pkg install vm-bhyve grub2-bhyve

# Load kernel modules
sudo kldload vmm nmdm

# Create VM storage
sudo zfs create zroot/vm
sudo sysrc vm_enable="YES"
sudo sysrc vm_dir="zfs:zroot/vm"
sudo vm init

# Create network switch (replace re0 with your interface)
sudo vm switch create public
sudo vm switch add public re0

# Download FreeBSD ISO
sudo vm iso https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/15.0/FreeBSD-15.0-RELEASE-amd64-disc1.iso

# Create and install VM
sudo vm create -s 20G vlabel-test
sudo vm install vlabel-test FreeBSD-15.0-RELEASE-amd64-disc1.iso
sudo vm console vlabel-test
```

#### Automated Setup

```bash
sudo ./scripts/setup-vm.sh
```

#### Testing the Module

```bash
# Get VM's IP (from console: ifconfig | grep inet)
sudo vm console vlabel-test

# In VM console - enable root SSH login (one-time setup):
echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
service sshd restart

# From host - copy module to VM
scp kernel/mac_vlabel.ko root@<vm-ip>:/root/

# Test in VM
ssh root@<vm-ip>
kldload /root/mac_vlabel.ko
sysctl security.mac.vlabel
kldunload mac_vlabel
```

#### VM Management Commands

```bash
sudo vm list                    # List all VMs
sudo vm start vlabel-test       # Start VM
sudo vm stop vlabel-test        # Stop VM
sudo vm stop -f vlabel-test     # Force stop (if hung)
sudo vm console vlabel-test     # Attach to console (~. to detach)
sudo vm destroy vlabel-test     # Delete VM
```

## Roadmap

### Current Status (MVP)
- [x] Module scaffolding with all entry point stubs
- [x] Compiles cleanly with WARNS=6
- [ ] Label structures and parsing
- [ ] Extended attribute integration
- [ ] Rule engine with first-match semantics
- [ ] /dev/vlabel device interface
- [ ] Audit ring buffer

### Future
- [ ] vlabeld daemon
- [ ] vlabelctl CLI tool
- [ ] Label transitions on exec
- [ ] Full context assertions
- [ ] Policy file parser

## Security Considerations

- Labels in `system` namespace require root to modify
- Module can only restrict access, never grant additional privileges
- Start in permissive mode to test policy before enforcing
- Always test in a VM before deploying to production

## License

BSD 2-Clause License. See individual source files for details.

## Contributing

Contributions welcome! Please:
1. Test changes in a VM
2. Ensure code compiles without warnings (`make WARNS=6`)
3. Follow FreeBSD kernel coding style
4. Add tests for new functionality

## References

- [FreeBSD MAC Framework](https://docs.freebsd.org/en/books/handbook/mac/)
- [mac(9) - Kernel MAC interface](https://man.freebsd.org/cgi/man.cgi?query=mac&sektion=9)
- [TrustedBSD Project](http://www.trustedbsd.org/)
