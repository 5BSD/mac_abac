# vLabel Policy Language

vLabel policies are written in JSON (or UCL, which is a superset of JSON). The policy file defines the enforcement mode, audit level, and access control rules.

## Policy Structure

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        { ... },
        { ... }
    ]
}
```

### Top-Level Fields

| Field | Values | Description |
|-------|--------|-------------|
| `mode` | `disabled`, `permissive`, `enforcing` | Enforcement mode |
| `audit` | `none`, `denials`, `decisions`, `verbose` | Audit verbosity |
| `rules` | Array of rule objects | Access control rules |

### Modes

- **disabled**: Module inactive, all operations allowed
- **permissive**: Rules evaluated and logged, but never denied
- **enforcing**: Rules actively enforced, violations denied

### Audit Levels

- **none**: No audit logging
- **denials**: Log denied operations only
- **decisions**: Log all policy decisions (allow and deny)
- **verbose**: Full debug logging

## Rule Structure

```json
{
    "id": 1,
    "action": "deny",
    "operations": ["exec", "mmap"],
    "subject": { "type": "untrusted" },
    "object": { "type": "system" },
    "context": { "jail": "host" },
    "newlabel": "type=privileged"
}
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique rule identifier (for removal/debugging) |
| `action` | Yes | `allow`, `deny`, or `transition` |
| `operations` | Yes | Array of operations this rule covers |
| `subject` | No | Pattern matching process label (default: any) |
| `object` | No | Pattern matching file label (default: any) |
| `context` | No | Additional context constraints |
| `newlabel` | Only for transition | New label string for transitions |

## Operations

Operations are the actions being controlled:

| Operation | Description |
|-----------|-------------|
| `exec` | Execute a file |
| `read` | Read file contents |
| `write` | Write to file |
| `open` | Open a file |
| `mmap` | Memory-map a file |
| `stat` | Get file metadata |
| `readdir` | List directory contents |
| `lookup` | Look up a name in directory |
| `create` | Create new file |
| `unlink` | Delete a file |
| `link` | Create hard link |
| `rename` | Rename a file |
| `chdir` | Change to directory |
| `setextattr` | Set extended attribute |
| `getextattr` | Get extended attribute |
| `access` | Check file accessibility |
| `all` | All operations (0xFFFF) |

Multiple operations in one rule:
```json
"operations": ["read", "write", "open"]
```

## Patterns

Patterns match against labels. An empty pattern or `*` matches any label.

### Subject Pattern (Process)

```json
"subject": {
    "type": "app",
    "domain": "web"
}
```

Matches processes with label `type=app,domain=web,...`

### Object Pattern (File)

```json
"object": {
    "type": "trusted",
    "domain": "system"
}
```

Matches files with label `type=trusted,domain=system,...`

### Pattern Fields

| Field | Description |
|-------|-------------|
| `type` | Match the `type=` value |
| `domain` | Match the `domain=` value |
| `name` | Match the `name=` value |
| `level` | Match the `level=` value |
| `negate` | If true, invert the match |

### Wildcard Patterns

Match any subject or object:
```json
"subject": {}
```
or simply omit the field.

### Negated Patterns

Match labels that DON'T have a specific value:
```json
"object": {
    "type": "trusted",
    "negate": true
}
```

This matches any file NOT labeled `type=trusted`.

## Context Constraints

Context constraints add conditions beyond label matching:

```json
"context": {
    "jail": "host",
    "sandboxed": false,
    "uid": 0
}
```

### Context Fields

| Field | Values | Description |
|-------|--------|-------------|
| `jail` | `"host"`, `"any"`, or number | Jail constraint |
| `sandboxed` | `true`/`false` | Capsicum capability mode |
| `uid` | number | Effective UID |
| `gid` | number | Effective GID |
| `tty` | `true`/`false` | Has controlling terminal |

### Jail Constraints

- `"host"` - Process must be on host (jail ID 0)
- `"any"` - Process must be in any jail (not host)
- `123` - Process must be in jail ID 123

Example: Only allow host processes to exec system binaries:
```json
{
    "id": 5,
    "action": "allow",
    "operations": ["exec"],
    "object": { "type": "system" },
    "context": { "jail": "host" }
}
```

## Actions

### allow

Permits the operation:
```json
{
    "id": 1,
    "action": "allow",
    "operations": ["read"],
    "subject": { "domain": "web" },
    "object": { "domain": "web" }
}
```

### deny

Blocks the operation with EACCES:
```json
{
    "id": 2,
    "action": "deny",
    "operations": ["exec"],
    "object": { "type": "untrusted" }
}
```

### transition

Changes the process label on exec:
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

When a `type=user` process executes a file labeled `type=setuid,name=su`, its label becomes `type=privileged,domain=system`.

## Rule Evaluation

Rules are evaluated in order (by `id`). First match wins.

1. For each access check, iterate through rules
2. Check if operation matches rule's operations bitmask
3. Check if subject label matches rule's subject pattern
4. Check if object label matches rule's object pattern
5. Check if context constraints match
6. If all match: apply action and stop
7. If no rule matches: **default deny**

### Evaluation Order

Lower IDs are evaluated first. Structure your policy with:
1. Specific deny rules (low IDs)
2. Specific allow rules (medium IDs)
3. General allow rules for trusted (high IDs)
4. Default deny is implicit (no matching rule = deny)

## Complete Example

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "untrusted" },
            "comment": "Never execute untrusted binaries"
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read", "write", "open", "stat"],
            "subject": { "domain": "web" },
            "object": { "domain": "web" },
            "comment": "Web apps access web files"
        },
        {
            "id": 3,
            "action": "allow",
            "operations": ["read", "write", "open", "stat"],
            "subject": { "domain": "database" },
            "object": { "domain": "database" },
            "comment": "Database apps access database files"
        },
        {
            "id": 4,
            "action": "deny",
            "operations": ["read", "write", "exec"],
            "object": { "level": "confidential" },
            "comment": "Block access to confidential unless explicitly allowed"
        },
        {
            "id": 5,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "confidential" },
            "object": { "level": "confidential" },
            "comment": "Confidential processes can read confidential data"
        },
        {
            "id": 10,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "setuid", "name": "su" },
            "newlabel": "type=privileged,domain=system",
            "comment": "Transition to privileged on su"
        },
        {
            "id": 100,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "trusted" },
            "comment": "Trusted processes can do anything"
        },
        {
            "id": 999,
            "action": "deny",
            "operations": ["all"],
            "comment": "Default deny everything else"
        }
    ]
}
```

## Line Format (Alternative)

For simple rules, a line-based format is also supported:

```
action operations subject -> object [context]
```

Examples:
```
deny exec * -> type=untrusted
allow read,write domain=web -> domain=web
allow all type=trusted -> *
```

Use with vlabelctl:
```sh
vlabelctl rule add "deny exec * -> type=untrusted"
```

## Loading Policy

### Via vlabeld

```sh
# Test syntax
vlabeld -t -v -c /etc/vlabel/policy.conf

# Load and run daemon
vlabeld -c /etc/vlabel/policy.conf

# Reload on SIGHUP
kill -HUP $(cat /var/run/vlabeld.pid)
```

### Via vlabelctl

```sh
# Add individual rules
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule add "allow all type=trusted -> *"

# Clear all rules
vlabelctl rule clear

# Remove specific rule
vlabelctl rule remove 5
```
