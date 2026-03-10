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
# Set a label on a file (live relabeling - takes effect immediately)
vlabelctl label set /usr/local/bin/myapp "type=trusted,domain=system"

# Get a file's label
vlabelctl label get /usr/local/bin/myapp
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

### File Labels (Extended Attributes)

| Limit | Value | Notes |
|-------|-------|-------|
| Label size | 4 KB | Total extattr size |
| Key length | 64 bytes | Per key |
| Value length | 256 bytes | Per value |
| Key-value pairs | 16 | Per label |

### Rule Patterns

| Limit | Value | Notes |
|-------|-------|-------|
| Max rules | 1,024 | System-wide |
| Key length | 64 bytes | Per key |
| Value length | 64 bytes | Per value (shorter than labels) |
| Key-value pairs | 8 | Per pattern (subject or object) |
| Rule size | ~2.1 KB | Non-transition rules |
| Rule size | ~11 KB | Transition rules (includes newlabel) |

Note: Rule patterns use smaller limits than file labels because pattern values
are short identifiers (type names, domains), while file labels may contain paths
or descriptions. This reduces per-rule memory from ~19KB to ~2KB.

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

### ZFS Only

This module is designed for ZFS filesystems. UFS with `MNT_MULTILABEL` is not
supported - the `setfmac`/`getfmac` hooks have been removed. Use `vlabelctl`
for all label operations.

### Module Unloading Not Supported

The module can be loaded after boot via `kldload`, but does not support
runtime unloading. This follows the pattern of MAC modules that allocate
per-object labels using UMA zones - labels may still be attached to kernel
objects (vnodes, credentials) when `mpo_destroy` is called, making safe
unload impossible.

For development/testing, **reboot** between module updates instead of trying
to unload/reload. The module omits `MPC_LOADTIME_FLAG_UNLOADOK` to enforce
this at the kernel level.

### Live Relabeling

Use `vlabelctl label set` to change labels on files. This writes the extended
attribute and immediately refreshes the kernel's cached label via the
`VLABEL_SYS_REFRESH` syscall. Changes take effect instantly without rebooting.

**Note:** Using `setextattr` directly only writes to disk - the cached label
won't update until the vnode is reclaimed. Always use `vlabelctl label set`.

## Requirements

- FreeBSD 15.0 or later
- Kernel compiled with `options MAC`
- ZFS filesystem

## License

BSD-2-Clause
