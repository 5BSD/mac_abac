# vLabel Examples

## Block Untrusted Executables

```sh
# Label untrusted files
vlabelctl label set /home/user/Downloads/sketch.sh "type=untrusted"

# Add rule
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule add "allow exec * -> *"

# Enable
sysctl security.mac.vlabel.mode=2
```

## Domain Isolation

Isolate web and database services:

```sh
# Label binaries
vlabelctl label set /usr/local/sbin/nginx "type=app,domain=web"
vlabelctl label set /usr/local/bin/postgres "type=app,domain=database"

# Label data directories
find /var/www -exec vlabelctl label set {} "type=data,domain=web" \;
find /var/db/postgres -exec vlabelctl label set {} "type=data,domain=database" \;

# Rules
vlabelctl rule add "allow read,write domain=web -> domain=web"
vlabelctl rule add "allow read,write domain=database -> domain=database"
vlabelctl rule add "deny read,write domain=web -> domain=database"
vlabelctl rule add "allow exec * -> *"
```

## Label Transitions

Change process label on exec:

```sh
# Label setuid binary
vlabelctl label set /usr/bin/su "type=setuid,name=su"

# Transition rule
vlabelctl rule add "transition exec type=user -> type=setuid,name=su => type=privileged"
```

When `type=user` process executes `/usr/bin/su`, it becomes `type=privileged`.

## Jail Restrictions

Block jailed processes from host resources:

```sh
# Label host-only files
vlabelctl label set /etc/master.passwd "scope=host"

# Rule with context - ctx: before -> applies to subject
vlabelctl rule add "deny read * ctx:jail=any -> scope=host"
vlabelctl rule add "allow read * -> *"
```

## Capsicum Sandbox Protection

Prevent debugging sandboxed processes:

```sh
# ctx: after -> applies to object (target process)
vlabelctl rule add "deny debug * -> * ctx:sandboxed=true"
vlabelctl rule add "allow debug * -> *"
```

## Context Constraint Syntax

Context constraints use `ctx:` with position determining what they apply to:

```sh
# ctx: BEFORE -> = subject constraint (caller)
# ctx: AFTER  -> = object constraint (target)

# Only root on host can access system files
deny read * ctx:jail=any -> type=system        # jailed users blocked
deny read * ctx:uid=1000 -> type=system        # non-root blocked
allow read * ctx:uid=0,jail=host -> type=system  # root on host allowed

# Protect sandboxed processes from debugging
deny debug * -> * ctx:sandboxed=true

# Both subject and object context
deny debug * ctx:uid=0 -> * ctx:sandboxed=true  # root can't debug sandboxed
```

## DTrace Debugging

```sh
# Watch denials
dtrace -n 'vlabel:::check-deny { printf("%s -> %s", stringof(arg0), stringof(arg1)); }'

# Measure latency
dtrace -n 'vlabel:::check-entry { self->ts = timestamp; }
           vlabel:::check-return /self->ts/ { @["ns"] = quantize(timestamp - self->ts); }'
```

## Policy File

`/etc/vlabel/policy.conf`:
```json
{
    "mode": "enforcing",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "untrusted" }
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["exec"],
            "subject": { "type": "trusted" }
        }
    ]
}
```

Load with:
```sh
vlabeld -c /etc/vlabel/policy.conf
```
