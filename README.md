# ABAC - FreeBSD MAC Module for ZFS

Label-based mandatory access control using extended attributes. **ZFS only.**

## Quick Start

```sh
# Build
cd kernel && make SYSDIR=/usr/src/sys
cd tools && make

# Load and label
kldload ./kernel/mac_abac.ko
mac_abac_ctl label set /usr/local/bin/myapp "type=trusted,domain=web"

# Add rules and enforce
mac_abac_ctl rule add "deny exec * -> type=untrusted"
sysctl security.mac.mac_abac.mode=2
```

## Components

| Component | Description |
|-----------|-------------|
| `kernel/mac_abac.ko` | MACF kernel module |
| `daemon/mac_abacd` | Policy daemon (JSON/UCL config) |
| `tools/mac_abac_ctl` | CLI for labels, rules, stats |

## Documentation

- [Labels](docs/labels.md) - Label format, extended attributes
- [Policy](docs/policy.md) - Writing rules
- [Examples](docs/examples.md) - Real-world scenarios
- [Architecture](docs/architecture.md) - System design, DTrace probes
- [Tools](docs/tools.md) - mac_abac_ctl and mac_abacd usage

## Supported Operations

| Operation | Hook | Description |
|-----------|------|-------------|
| `exec` | vnode | Execute files |
| `read` | vnode | Read file contents |
| `write` | vnode | Write file contents |
| `open` | vnode | Open files |
| `mmap` | vnode | Memory-map files |
| `access` | vnode | access() syscall |
| `setextattr` | vnode | Modify labels (protects `system:mac_abac`) |
| `getextattr` | vnode | Read labels |
| `debug` | proc | ptrace/procfs debugging |
| `signal` | proc | Send signals |
| `sched` | proc | Scheduler operations |

## Sysctls

| Sysctl | Values | Description |
|--------|--------|-------------|
| `security.mac.mac_abac.mode` | 0/1/2 | Disabled/Permissive/Enforcing |
| `security.mac.mac_abac.default_policy` | 0/1 | Allow/Deny when no rule matches |

## Module Loading

There are two ways to load the kernel module:

### Manual Loading (Development)

```sh
# Copy module to VM and load manually
scp kernel/mac_abac.ko root@vm:/root/
ssh root@vm 'kldload /root/mac_abac.ko'
```

Module is loaded once; lost on reboot. Good for quick testing.

### Auto-Loading at Boot (Production/Testing VMs)

```sh
# Install to boot kernel directory (preferred location)
scp kernel/mac_abac.ko root@vm:/boot/kernel/

# Enable in loader.conf (on the VM)
echo 'mac_abac_load="YES"' >> /boot/loader.conf
```

Module loads automatically at boot, before userland starts. **This is the recommended setup for test VMs.**

**Important:** FreeBSD searches `/boot/kernel/` before `/boot/modules/`. Check where your module loads from:

```sh
kldstat -v | grep mac_abac
# Output shows: (/boot/kernel/mac_abac.ko) or (/boot/modules/mac_abac.ko)
```

If you have copies in multiple locations, the kernel uses this search order:
1. `/boot/kernel/` (base system modules)
2. `/boot/modules/` (third-party modules)

Always update the copy that's actually being loaded.

### Updating the Module

The module cannot be unloaded (by design - orphaned labels would crash the kernel). To update:

1. Find where the module is loaded from:
   ```sh
   ssh root@vm 'kldstat -v | grep mac_abac'
   # Shows: (/boot/kernel/mac_abac.ko) or similar
   ```

2. Copy new `.ko` to that **exact location**:
   ```sh
   scp kernel/mac_abac.ko root@vm:/boot/kernel/   # or wherever kldstat showed
   ```

3. Reboot the system:
   ```sh
   ssh root@vm reboot
   ```

**Troubleshooting:** If debug spam persists after reboot, verify the correct file was updated:
```sh
# Check MD5 matches between local and VM
md5sum kernel/mac_abac.ko                           # local
ssh root@vm 'md5 /boot/kernel/mac_abac.ko'          # VM - must match!

# Find all copies on VM
ssh root@vm 'find / -name mac_abac.ko 2>/dev/null'
```

### Debug vs Release Builds

```sh
# Release build (no console spam)
make SYSDIR=/usr/src/sys

# Debug build (verbose logging to console)
make SYSDIR=/usr/src/sys ABAC_DEBUG=1
```

## Known Limitations

- **ZFS only** - UFS multilabel not supported. Use `mac_abac_ctl`, not `getfmac`/`setfmac`.
- **No module unload** - Reboot to update module (see above).

See [Architecture](docs/architecture.md) for details on the ZFS-only design.

## Requirements

- FreeBSD 15.0+
- `options MAC` in kernel
- ZFS filesystem

## License

BSD-2-Clause
