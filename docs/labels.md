# ABAC Labels

Labels are key-value pairs that define security attributes for files and processes.

## Format

Labels are comma-separated `key=value` pairs:

```
type=app,domain=web,name=nginx
```

Internally stored as newline-separated in extended attributes:
```
type=app
domain=web
name=nginx
```

## Storage

Labels are stored in the `system:mac_abac` extended attribute namespace.

```sh
# View raw extended attribute
getextattr system mac_abac /path/to/file

# Use mac_abac_ctl (preferred)
mac_abac_ctl label get /path/to/file
```

## Setting Labels

```sh
# Basic set (writes extattr, then refreshes cache)
mac_abac_ctl label set /path/to/file "type=trusted,domain=web"

# Atomic set (single kernel syscall - preferred for ZFS)
mac_abac_ctl label setatomic /path/to/file "type=trusted,domain=web"

# Recursive labeling
mac_abac_ctl label setrecursive /var/www "type=data,domain=web"
mac_abac_ctl label setrecursive /var/www "type=data" -v      # Verbose
mac_abac_ctl label setrecursive /var/www "type=data" -d      # Directories only
mac_abac_ctl label setrecursive /var/www "type=data" -f      # Files only
```

## Cache Refresh

The kernel caches labels in memory for performance. If you modify labels directly
with `setextattr`, refresh the cache:

```sh
mac_abac_ctl label refresh /path/to/file
```

Using `mac_abac_ctl label set` or `setatomic` handles this automatically.

## Default Labels

Files and processes without explicit labels receive a default label:
```
type=unlabeled
```

This matches the wildcard `*` in rules but not specific patterns.

## Limits

| Limit | Value |
|-------|-------|
| Max label length | 4,096 bytes |
| Max key length | 64 bytes |
| Max value length | 256 bytes |
| Max pairs per label | 16 |

## Common Label Conventions

| Key | Purpose | Examples |
|-----|---------|----------|
| `type` | Object category | `app`, `data`, `config`, `log`, `system`, `untrusted` |
| `domain` | Security domain | `web`, `database`, `mail`, `admin` |
| `name` | Application name | `nginx`, `postgres`, `sendmail` |
| `sensitivity` | Classification | `public`, `internal`, `confidential`, `secret` |
| `compartment` | Need-to-know | `hr`, `finance`, `engineering` |
| `restricted` | Sandbox flag | `true`, `false` |

## Pattern Matching

In rules, patterns match labels:

| Pattern | Matches |
|---------|---------|
| `*` | Any label (wildcard) |
| `type=app` | Labels with `type=app` |
| `type=*` | Labels with any `type` value |
| `type=app,domain=web` | Labels with both pairs (AND logic) |
| `!type=untrusted` | Labels that do NOT have `type=untrusted` |

## Process Labels

Process labels are:
- Inherited from parent at fork
- Changed via transition rules at exec
- Stored in credential structure (not extended attributes)

```sh
# Transition rule: change label on exec
mac_abac_ctl rule add "transition exec * -> type=entrypoint,app=nginx => domain=web,app=nginx"
```

## ZFS-Only Design

ABAC uses extended attributes via `VOP_GETEXTATTR`/`VOP_SETEXTATTR`.
ZFS supports this natively. UFS `multilabel` mode is **not** supported.

Standard FreeBSD MAC tools (`getfmac`/`setfmac`) will not work.
Always use `mac_abac_ctl` for label management.
