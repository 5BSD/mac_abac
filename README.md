# ABAC - FreeBSD MAC Module

Label-based mandatory access control using extended attributes. Supports **UFS** (with multilabel) and **ZFS**.

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

- [Admin Guide](docs/admin-guide.md) - Sysctls, syscalls, ZFS/UFS behavior, security
- [Labels](docs/labels.md) - Label format, extended attributes
- [Policy](docs/policy.md) - Writing rules
- [Examples](docs/examples.md) - Real-world scenarios
- [Architecture](docs/architecture.md) - System design, DTrace probes
- [Tools](docs/tools.md) - mac_abac_ctl and mac_abacd usage

## Supported Operations

### File/Vnode Operations
| Operation | Description |
|-----------|-------------|
| `exec` | Execute files |
| `read` | Read file contents |
| `write` | Write file contents |
| `open` | Open files |
| `mmap` | Memory-map files |
| `mprotect` | Change memory protection |
| `access` | access() syscall |
| `stat` | Get file status |
| `readdir` | Read directory contents |
| `create` | Create new files |
| `lookup` | Look up files in directories |
| `link` | Create hard links |
| `rename` | Rename files |
| `unlink` | Delete files |
| `chdir` | Change directory |
| `setextattr` | Set extended attributes |
| `getextattr` | Get extended attributes |

### Process Operations
| Operation | Description |
|-----------|-------------|
| `debug` | ptrace/procfs debugging |
| `signal` | Send signals |
| `sched` | Scheduler operations |
| `wait` | Wait on processes |

### Socket Operations
| Operation | Description |
|-----------|-------------|
| `connect` | Socket connect |
| `bind` | Bind to address |
| `listen` | Listen for connections |
| `accept` | Accept connections |
| `send` | Send data |
| `receive` | Receive data |
| `deliver` | Packet delivery |

### System Operations
| Operation | Description |
|-----------|-------------|
| `audit` | Audit operations |
| `all` | All operations (wildcard) |

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

- **No module unload** - Reboot to update module (see above).
- Use `mac_abac_ctl`, not `getfmac`/`setfmac` (standard MAC tools don't work with our label format).

## Requirements

- FreeBSD 15.0+
- `options MAC` in kernel
- UFS with `multilabel` mount option, or ZFS

## Filesystem Support

| Filesystem | Label Loading | Notes |
|------------|---------------|-------|
| **UFS** | Immediate (via MAC framework) | Requires `multilabel` mount option |
| **ZFS** | Late/lazy (on first access) | Uses `ABAC_SYS_SETLABEL` syscall; labels cached in vnode |

See [Admin Guide](docs/admin-guide.md) for detailed behavior differences and security considerations.

## Related Tools

For bulk binary labeling, see **maclabel** in [FreeBSDKit](https://github.com/vIsNotUNIX/FreeBSDKit) (`Sources/mac-policy-cli`). It reads JSON configuration files and applies labels recursively to directories, with Capsicum sandboxing.

## License

BSD-2-Clause
