# vLabel - FreeBSD Mandatory Access Control Framework Module

vLabel is a label-based mandatory access control (MAC) policy module for FreeBSD. It uses extended attributes to persistently store security labels on files and enforces access control rules based on subject (process) and object (file) labels.

## Features

- **Persistent Labels**: Labels stored in `system:vlabel` extended attributes survive reboots
- **Flexible Policy Language**: JSON/UCL configuration with pattern matching and wildcards
- **Context-Aware Rules**: Match on jail ID, Capsicum sandbox mode, UID/GID
- **Label Transitions**: Automatically change process labels on exec (like setuid for labels)
- **Audit System**: Ring buffer audit log accessible via `/dev/vlabel`
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
| `security.mac.vlabel.audit_level` | 0-3 | None/Denials/Decisions/Verbose |

## Requirements

- FreeBSD 15.0 or later
- Kernel compiled with `options MAC`
- UFS or ZFS filesystem (for extended attributes)

## License

BSD-2-Clause
