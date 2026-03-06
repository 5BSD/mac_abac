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

Using FreeBSD tools:
```sh
# Set a label
setextattr system vlabel "type=trusted,domain=system" /path/to/file

# Get a label
getextattr system vlabel /path/to/file

# Remove a label
rmextattr system vlabel /path/to/file
```

Using vlabelctl:
```sh
vlabelctl label set /path/to/file "type=trusted,domain=system"
vlabelctl label get /path/to/file
vlabelctl label remove /path/to/file
```

### Filesystem Requirements

Extended attributes require:
- **UFS**: Mount with `extattr` support (default on FreeBSD)
- **ZFS**: Native extended attribute support (always available)

### Permissions

Setting labels in the `system` namespace requires root privileges. This prevents unprivileged users from modifying security labels.

## Process Labels (Subject Labels)

Processes have labels too. These are called "subject labels" in MAC terminology.

### Label Inheritance

By default, a child process inherits its parent's label:

```
Process A (type=app,domain=web)
    └── fork() → Process B (type=app,domain=web)
```

### Label Transitions

When a process executes a binary with a transition rule, its label changes:

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

### Default Labels

Files without a `system:vlabel` extended attribute get a default label. Processes started before the module loads get a default label. The default label matches rules with empty/wildcard patterns.

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
setextattr system vlabel "type=trusted,domain=system" /bin/*
setextattr system vlabel "type=trusted,domain=system" /sbin/*

# User applications - semi-trusted
setextattr system vlabel "type=app,domain=user" /usr/local/bin/*

# Downloads - untrusted
setextattr system vlabel "type=untrusted" /home/*/Downloads/*
```

### By Application Domain

```sh
# Web server files
setextattr system vlabel "type=app,domain=web" /usr/local/www/*
setextattr system vlabel "type=data,domain=web" /var/www/*

# Database files
setextattr system vlabel "type=app,domain=database" /usr/local/bin/postgres
setextattr system vlabel "type=data,domain=database" /var/db/postgres/*
```

### By Sensitivity

```sh
# Public data
setextattr system vlabel "level=public" /var/www/public/*

# Internal data
setextattr system vlabel "level=internal" /var/data/internal/*

# Confidential data
setextattr system vlabel "level=confidential" /var/data/secure/*
```

## Label Caching

The kernel caches parsed labels for performance. Labels are read from extended attributes when a file is first accessed and cached in the vnode. The cache is invalidated when:

- The extended attribute is modified
- The vnode is reclaimed (file closed by all processes)
- The filesystem is unmounted
