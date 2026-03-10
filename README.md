# vLabel - FreeBSD MAC Module for ZFS

Label-based mandatory access control using extended attributes. **ZFS only.**

## Quick Start

```sh
# Build
cd kernel && make SYSDIR=/usr/src/sys
cd tools && make

# Load and label
kldload ./kernel/mac_vlabel.ko
vlabelctl label set /usr/local/bin/myapp "type=trusted,domain=web"

# Add rules and enforce
vlabelctl rule add "deny exec * -> type=untrusted"
sysctl security.mac.vlabel.mode=2
```

## Components

| Component | Description |
|-----------|-------------|
| `kernel/mac_vlabel.ko` | MACF kernel module |
| `daemon/vlabeld` | Policy daemon (JSON/UCL config) |
| `tools/vlabelctl` | CLI for labels, rules, stats |

## Documentation

- [Labels](docs/labels.md) - Label format, extended attributes
- [Policy](docs/policy.md) - Writing rules
- [Examples](docs/examples.md) - Real-world scenarios
- [Architecture](docs/architecture.md) - System design, DTrace probes
- [Tools](docs/tools.md) - vlabelctl and vlabeld usage

## Supported Operations

| Operation | Hook | Description |
|-----------|------|-------------|
| `exec` | vnode | Execute files |
| `read` | vnode | Read file contents |
| `write` | vnode | Write file contents |
| `open` | vnode | Open files |
| `mmap` | vnode | Memory-map files |
| `access` | vnode | access() syscall |
| `setextattr` | vnode | Modify labels (protects `system:vlabel`) |
| `getextattr` | vnode | Read labels |
| `debug` | proc | ptrace/procfs debugging |
| `signal` | proc | Send signals |
| `sched` | proc | Scheduler operations |

## Sysctls

| Sysctl | Values | Description |
|--------|--------|-------------|
| `security.mac.vlabel.mode` | 0/1/2 | Disabled/Permissive/Enforcing |
| `security.mac.vlabel.default_policy` | 0/1 | Allow/Deny when no rule matches |

## Module Loading

There are two ways to load the kernel module:

### Manual Loading (Development)

```sh
# Copy module to VM and load manually
scp kernel/mac_vlabel.ko root@vm:/root/
ssh root@vm 'kldload /root/mac_vlabel.ko'
```

Module is loaded once; lost on reboot. Good for quick testing.

### Auto-Loading at Boot (Production/Testing VMs)

```sh
# Install to boot kernel directory (preferred location)
scp kernel/mac_vlabel.ko root@vm:/boot/kernel/

# Enable in loader.conf (on the VM)
echo 'mac_vlabel_load="YES"' >> /boot/loader.conf
```

Module loads automatically at boot, before userland starts. **This is the recommended setup for test VMs.**

**Important:** FreeBSD searches `/boot/kernel/` before `/boot/modules/`. Check where your module loads from:

```sh
kldstat -v | grep vlabel
# Output shows: (/boot/kernel/mac_vlabel.ko) or (/boot/modules/mac_vlabel.ko)
```

If you have copies in multiple locations, the kernel uses this search order:
1. `/boot/kernel/` (base system modules)
2. `/boot/modules/` (third-party modules)

Always update the copy that's actually being loaded.

### Updating the Module

The module cannot be unloaded (by design - orphaned labels would crash the kernel). To update:

1. Find where the module is loaded from:
   ```sh
   ssh root@vm 'kldstat -v | grep vlabel'
   # Shows: (/boot/kernel/mac_vlabel.ko) or similar
   ```

2. Copy new `.ko` to that **exact location**:
   ```sh
   scp kernel/mac_vlabel.ko root@vm:/boot/kernel/   # or wherever kldstat showed
   ```

3. Reboot the system:
   ```sh
   ssh root@vm reboot
   ```

**Troubleshooting:** If debug spam persists after reboot, verify the correct file was updated:
```sh
# Check MD5 matches between local and VM
md5sum kernel/mac_vlabel.ko                           # local
ssh root@vm 'md5 /boot/kernel/mac_vlabel.ko'          # VM - must match!

# Find all copies on VM
ssh root@vm 'find / -name mac_vlabel.ko 2>/dev/null'
```

### Debug vs Release Builds

```sh
# Release build (no console spam)
make SYSDIR=/usr/src/sys

# Debug build (verbose logging to console)
make SYSDIR=/usr/src/sys VLABEL_DEBUG=1
```

## Known Limitations

- **ZFS only** - UFS multilabel not supported. Use `vlabelctl`, not `getfmac`/`setfmac`.
- **No module unload** - Reboot to update module (see above).

See [Architecture](docs/architecture.md) for details on the ZFS-only design.

## Requirements

- FreeBSD 15.0+
- `options MAC` in kernel
- ZFS filesystem

## License

BSD-2-Clause
