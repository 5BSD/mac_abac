# vLabel - FreeBSD Mandatory Access Control Framework Module

vLabel is a label-based mandatory access control (MAC) policy module for FreeBSD. It uses extended attributes to persistently store security labels on files and enforces access control rules based on subject (process) and object (file) labels.

## Features

- **Persistent Labels**: Labels stored in `system:vlabel` extended attributes survive reboots
- **Flexible Policy Language**: JSON/UCL configuration with pattern matching and wildcards
- **Context-Aware Rules**: Match on jail ID, Capsicum sandbox mode, UID/GID
- **Label Transitions**: Automatically change process labels on exec (like setuid for labels)
- **DTrace Probes**: Built-in probes for real-time tracing and debugging
- **Multiple Modes**: Disabled, permissive (log only), or enforcing

## Quick Start

### 1. Build

```sh
# Build kernel module
cd kernel && make SYSDIR=/usr/src/sys

# Build daemon and tools
cd daemon && make
cd tools && make
```

### 2. Load Module

```sh
kldload ./kernel/mac_vlabel.ko
```

### 3. Label Files

```sh
# Set a label on a file
setextattr system vlabel "type=trusted,domain=system" /usr/local/bin/myapp

# Or use vlabelctl
vlabelctl label set /usr/local/bin/myapp "type=trusted,domain=system"
```

### 4. Load Policy

```sh
# Test policy syntax
vlabeld -t -v -c /etc/vlabel/policy.conf

# Run daemon (loads policy and monitors audit events)
vlabeld -c /etc/vlabel/policy.conf
```

### 5. Enable Enforcement

```sh
# Permissive mode (log but don't block)
sysctl security.mac.vlabel.mode=1

# Enforcing mode (actively block)
sysctl security.mac.vlabel.mode=2
```

## Components

| Component | Description |
|-----------|-------------|
| `kernel/mac_vlabel.ko` | MACF kernel module |
| `daemon/vlabeld` | Policy daemon - loads rules, monitors audit |
| `tools/vlabelctl` | CLI for labels, rules, stats, monitoring |

## Documentation

- [Label Format](docs/labels.md) - How labels work, extended attributes
- [Policy Language](docs/policy.md) - Writing rules in JSON/UCL
- [Examples](docs/examples.md) - Comprehensive examples: jails, Capsicum, transitions, real-world scenarios
- [Architecture](docs/architecture.md) - System design, kernel hooks
- [Tools Reference](docs/tools.md) - vlabelctl and vlabeld usage

## Example Policy

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "untrusted" }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read", "write", "open"],
            "subject": { "domain": "web" },
            "object": { "domain": "web" }
        },
        {
            "id": 100,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "trusted" }
        }
    ]
}
```

## Sysctls

| Sysctl | Values | Description |
|--------|--------|-------------|
| `security.mac.vlabel.enabled` | 0/1 | Enable/disable module |
| `security.mac.vlabel.mode` | 0/1/2 | Disabled/Permissive/Enforcing |
| `security.mac.vlabel.default_policy` | 0/1 | Allow/Deny when no rule matches |

## Limits

| Limit | Value | Scope |
|-------|-------|-------|
| Label size | 4 KB | Per label |
| Key length | 64 bytes | Per key |
| Value length | 256 bytes | Per value |
| Key-value pairs | 16 | Per label |
| Rules | 1,024 | System-wide |

Note: The mac_syscall interface uses variable-length structures, eliminating the
previous ioctl size limitations. These limits are designed for practical use while
maintaining reasonable kernel memory usage.

## DTrace Probes

vLabel provides DTrace probes for debugging and monitoring:

```sh
# Watch all denied accesses
dtrace -n 'vlabel:::check-deny { printf("%s -> %s op=0x%x rule=%u",
    stringof(arg0), stringof(arg1), arg2, arg3); }'

# Count denials by operation
dtrace -n 'vlabel:::check-deny { @[arg2] = count(); }'

# Measure access check latency
dtrace -n 'vlabel:::check-entry { self->ts = timestamp; }
           vlabel:::check-return /self->ts/ {
               @["ns"] = quantize(timestamp - self->ts);
               self->ts = 0;
           }'

# Watch label transitions
dtrace -n 'vlabel:::transition-exec {
    printf("pid %d: %s -> %s", arg3, stringof(arg0), stringof(arg1)); }'
```

Available probes: `check-entry`, `check-return`, `check-allow`, `check-deny`,
`rule-match`, `rule-nomatch`, `transition-exec`, `extattr-read`, `extattr-default`,
`rule-add`, `rule-remove`, `rule-clear`, `mode-change`.

See [Architecture](docs/architecture.md#dtrace-integration) for full probe documentation.

## Known Limitations

### Module Unloading Not Supported

The module can be loaded after boot via `kldload`, but does not support
runtime unloading. This follows the pattern of MAC modules that allocate
per-object labels using UMA zones - labels may still be attached to kernel
objects (vnodes, credentials) when `mpo_destroy` is called, making safe
unload impossible.

For development/testing, **reboot** between module updates instead of trying
to unload/reload. The module omits `MPC_LOADTIME_FLAG_UNLOADOK` to enforce
this at the kernel level.

### Vnode Label Caching

File labels are read from extended attributes when the kernel first accesses
a file's vnode. If you set a label on a file that has already been accessed,
the new label won't take effect until:

1. The vnode is reclaimed (system decides to free it), OR
2. The system is rebooted, OR
3. The module is loaded fresh (after a reboot)

For reliable label enforcement, set labels on files BEFORE loading the module,
or reboot after making label changes.

## Requirements

- FreeBSD 15.0 or later
- Kernel compiled with `options MAC`
- UFS or ZFS filesystem (for extended attributes)

## License

BSD-2-Clause
