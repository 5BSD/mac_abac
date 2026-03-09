# vLabel Labels

Labels are the core concept in vLabel. Every file can have a label, and every process inherits or transitions to a label. Access control rules match subject (process) labels against object (file) labels.

## Label Format

Labels are key-value pairs in a comma-separated string:

```
type=trusted,domain=system,name=sshd,level=high
```

### Standard Keys

| Key | Purpose | Examples |
|-----|---------|----------|
| `type` | Classification category | `trusted`, `untrusted`, `app`, `system`, `setuid` |
| `domain` | Isolation domain | `system`, `web`, `database`, `user`, `network` |
| `name` | Specific identifier | `nginx`, `postgres`, `su`, `passwd` |
| `level` | Sensitivity level | `public`, `internal`, `confidential`, `secret` |

You can use any keys - these are conventions, not requirements.

### Examples

```
type=trusted,domain=system           # System daemon
type=app,domain=web                  # Web application
type=untrusted                       # Untrusted binary
type=setuid,name=su                  # Privileged helper
type=data,domain=database,level=confidential  # Sensitive data file
```

## Extended Attributes

Labels are stored in the `system:vlabel` extended attribute namespace.

### Setting Labels

Use `vlabelctl` for live relabeling (recommended):
```sh
vlabelctl label set /path/to/file "type=trusted,domain=system"
vlabelctl label get /path/to/file
vlabelctl label remove /path/to/file
```

`vlabelctl label set` writes the extattr and immediately refreshes the kernel's cached label, so changes take effect instantly without requiring a reboot.

Using FreeBSD tools directly (not recommended - no live refresh):
```sh
# Set a label (won't update cached label until vnode is reclaimed)
setextattr system vlabel "type=trusted,domain=system" /path/to/file

# Get a label
getextattr system vlabel /path/to/file

# Remove a label
rmextattr system vlabel /path/to/file
```

**Note:** Using `setextattr` directly only writes to disk. The kernel's cached vnode label won't update until the file is closed and the vnode is reclaimed. Use `vlabelctl label set` for immediate effect.

### Filesystem Requirements

Extended attributes require:
- **UFS**: Mount with `extattr` support (default on FreeBSD)
- **ZFS**: Native extended attribute support (always available)

### Permissions

Setting labels in the `system` namespace requires root privileges. This prevents unprivileged users from modifying security labels.

## Process Labels (Subject Labels)

Processes have labels too. These are called "subject labels" in MAC terminology.

### Label Inheritance on Exec

When a process executes a binary, the process label is determined by these rules in priority order:

1. **Explicit Transition Rule**: If a `transition` rule matches the exec, the process gets the label specified by `newlabel` in the rule.

2. **Vnode Label**: If no transition rule matches but the executable has a label, the process inherits that label. This is the most common case.

3. **Parent Label**: If no transition rule and the executable is unlabeled, the process keeps its parent's label.

#### Example: Vnode Label Inheritance

```sh
# Label a binary
vlabelctl label set /usr/local/bin/myapp "type=app,domain=web"

# When executed, the process gets that label
/usr/local/bin/myapp &   # Process now has type=app,domain=web
```

#### Example: Fork Inheritance

Child processes created with `fork()` inherit their parent's label:

```
Process A (type=app,domain=web)
    └── fork() → Process B (type=app,domain=web)
```

### Explicit Transitions

When you need more control, use transition rules. These override vnode label inheritance:

```
Process A (type=user)
    └── exec(/usr/bin/su) → Process A' (type=privileged,domain=system)
```

Transition rules are defined in policy:

```json
{
    "id": 10,
    "action": "transition",
    "operations": ["exec"],
    "subject": { "type": "user" },
    "object": { "type": "setuid", "name": "su" },
    "newlabel": "type=privileged,domain=system"
}
```

Or in CLI format:
```
transition exec type=user -> type=setuid,name=su => type=privileged,domain=system
```

Use transition rules when:
- Different subjects should get different labels for the same executable
- You want to restrict which subjects can transition
- The new label should differ from the vnode label

### Default Labels

When no explicit label exists, the default label `type=unlabeled` is assigned to both subjects and objects:

| Type | Default Label | When Used |
|------|---------------|-----------|
| **Subject (process)** | `type=unlabeled` | Processes started before module loads, or with unlabeled parent and unlabeled executable |
| **Object (file/vnode)** | `type=unlabeled` | Files without `system:vlabel` extended attribute |

This consistent default allows you to write rules targeting unclassified entities:
```
# Deny unlabeled processes from executing anything
deny exec type=unlabeled -> *

# Deny executing unlabeled files
deny exec * -> type=unlabeled

# Only labeled processes can access labeled files
deny all type=unlabeled -> !type=unlabeled
```

The wildcard `*` matches any label including defaults.

## Label Matching

Rules use patterns to match labels. A pattern specifies which fields to check:

| Pattern | Matches |
|---------|---------|
| `{ "type": "trusted" }` | Any label with `type=trusted` |
| `{ "domain": "web" }` | Any label with `domain=web` |
| `{ "type": "app", "domain": "web" }` | Labels with both `type=app` AND `domain=web` |
| `{}` or `*` | Any label (wildcard) |

### Negation

Patterns can be negated to match labels that DON'T have a field:

```json
{
    "type": "trusted",
    "negate": true
}
```

This matches any label that does NOT have `type=trusted`.

## Viewing Labels in Bulk

List all labeled files in a directory:
```sh
find /path -exec getextattr -q system vlabel {} \; 2>/dev/null
```

Or with a script:
```sh
#!/bin/sh
for f in "$@"; do
    label=$(getextattr -q system vlabel "$f" 2>/dev/null)
    if [ -n "$label" ]; then
        echo "$f: $label"
    fi
done
```

## Common Labeling Strategies

### By Trust Level

```sh
# System binaries - fully trusted
for f in /bin/* /sbin/*; do
    vlabelctl label set "$f" "type=trusted,domain=system"
done

# User applications - semi-trusted
for f in /usr/local/bin/*; do
    vlabelctl label set "$f" "type=app,domain=user"
done

# Downloads - untrusted
for f in /home/*/Downloads/*; do
    vlabelctl label set "$f" "type=untrusted"
done
```

### By Application Domain

```sh
# Web server files
vlabelctl label set /usr/local/www/nginx "type=app,domain=web"
vlabelctl label set /var/www/html "type=data,domain=web"

# Database files
vlabelctl label set /usr/local/bin/postgres "type=app,domain=database"
vlabelctl label set /var/db/postgres "type=data,domain=database"
```

### By Sensitivity

```sh
# Public data
vlabelctl label set /var/www/public "level=public"

# Internal data
vlabelctl label set /var/data/internal "level=internal"

# Confidential data
vlabelctl label set /var/data/secure "level=confidential"
```

## Label Caching

The kernel caches parsed labels for performance. Labels are read from extended attributes when a file is first accessed and cached in the vnode.

### Live Relabeling

When using `vlabelctl label set`, the cached label is refreshed immediately via the `VLABEL_SYS_REFRESH` syscall. This enables live relabeling on all filesystems, including ZFS.

### Cache Invalidation

The cache is also invalidated when:
- The vnode is reclaimed (file closed by all processes)
- The filesystem is unmounted

**Note:** Using `setextattr` directly does NOT refresh the cached label. The new label won't take effect until the vnode is reclaimed. Always use `vlabelctl label set` for immediate effect.
