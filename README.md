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

## Sysctls

| Sysctl | Values | Description |
|--------|--------|-------------|
| `security.mac.vlabel.mode` | 0/1/2 | Disabled/Permissive/Enforcing |
| `security.mac.vlabel.default_policy` | 0/1 | Allow/Deny when no rule matches |

## Known Limitations

- **ZFS only** - UFS multilabel not supported. Use `vlabelctl`, not `getfmac`/`setfmac`.
- **No module unload** - Reboot to update module.
- **Exec enforcement only** - File read/write/mmap hooks are stubs (allow all).

See [Architecture](docs/architecture.md) for details on the ZFS-only design.

## Requirements

- FreeBSD 15.0+
- `options MAC` in kernel
- ZFS filesystem

## License

BSD-2-Clause
