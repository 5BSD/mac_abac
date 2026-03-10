# vLabel Policy Language

Policies are JSON/UCL files defining rules.

## Structure

```json
{
    "mode": "enforcing",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "untrusted" }
        }
    ]
}
```

## Mode

- `disabled` - Module inactive
- `permissive` - Log only, no enforcement
- `enforcing` - Active enforcement

## Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier |
| `action` | Yes | `allow`, `deny`, `transition` |
| `operations` | Yes | Array of operations |
| `subject` | No | Process label pattern |
| `object` | No | File label pattern |
| `subj_ctx` | No | Subject context constraints |
| `obj_ctx` | No | Object context constraints |
| `newlabel` | transition only | New label string |

## Operations

**Currently enforced:**
- `exec` - Execute a file
- `debug` - ptrace/procfs (process operations)
- `signal` - Signal delivery (process operations)
- `sched` - Scheduler operations (process operations)

**Defined but not enforced (stubs):**
- `read`, `write`, `open`, `mmap`, `stat`, `create`, `unlink`, etc.

Use `all` for all operations.

## Context Constraints

**UCL/JSON format:**
```json
"subj_ctx": { "jail": "host", "uid": 0 }
"obj_ctx": { "sandboxed": true }
```

| Field | Values |
|-------|--------|
| `jail` | `"host"`, `"any"`, or jail ID |
| `sandboxed` | `true`/`false` (Capsicum mode) |
| `uid` | Effective UID |
| `gid` | Effective GID |
| `tty` | `true`/`false` |

## CLI Syntax

```sh
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule add "allow exec type=trusted -> *"
vlabelctl rule add "transition exec * -> type=setuid => type=privileged"
```

Format: `action operations subject [ctx:...] -> object [ctx:...] [=> newlabel]`

**Context in CLI:** Position determines what `ctx:` applies to:
```sh
# ctx: BEFORE -> = subject constraint
# ctx: AFTER  -> = object constraint
# Multiple constraints: comma-separated (one ctx: per side)

vlabelctl rule add "deny exec * ctx:jail=any -> type=hostonly"
vlabelctl rule add "deny debug * -> * ctx:sandboxed=true"
vlabelctl rule add "deny debug * ctx:uid=0 -> * ctx:sandboxed=true"
vlabelctl rule add "allow exec * ctx:uid=0,jail=host -> type=admin"
```

## Rule Evaluation

First match wins. No match = default policy (configurable via sysctl).

## Loading

```sh
# Via daemon
vlabeld -c /etc/vlabel/policy.conf

# Via CLI
vlabelctl rule load /etc/vlabel/rules.conf
vlabelctl rule add "deny exec * -> type=untrusted"
```
