# ABAC Examples

## Block Untrusted Executables

```sh
# Label untrusted files
mac_abac_ctl label set /home/user/Downloads/sketch.sh "type=untrusted"

# Add rule
mac_abac_ctl rule add "deny exec * -> type=untrusted"
mac_abac_ctl rule add "allow exec * -> *"

# Enable
sysctl security.mac.mac_abac.mode=2
```

## Domain Isolation

Isolate web and database services:

```sh
# Label binaries
mac_abac_ctl label set /usr/local/sbin/nginx "type=app,domain=web"
mac_abac_ctl label set /usr/local/bin/postgres "type=app,domain=database"

# Label data directories
find /var/www -exec mac_abac_ctl label set {} "type=data,domain=web" \;
find /var/db/postgres -exec mac_abac_ctl label set {} "type=data,domain=database" \;

# Rules
mac_abac_ctl rule add "allow read,write domain=web -> domain=web"
mac_abac_ctl rule add "allow read,write domain=database -> domain=database"
mac_abac_ctl rule add "deny read,write domain=web -> domain=database"
mac_abac_ctl rule add "allow exec * -> *"
```

## Label Transitions

Change process label on exec:

```sh
# Label setuid binary
mac_abac_ctl label set /usr/bin/su "type=setuid,name=su"

# Transition rule
mac_abac_ctl rule add "transition exec type=user -> type=setuid,name=su => type=privileged"
```

When `type=user` process executes `/usr/bin/su`, it becomes `type=privileged`.

## Jail Restrictions

Block jailed processes from host resources:

```sh
# Label host-only files
mac_abac_ctl label set /etc/master.passwd "scope=host"

# Rule with context - ctx: before -> applies to subject
mac_abac_ctl rule add "deny read * ctx:jail=any -> scope=host"
mac_abac_ctl rule add "allow read * -> *"
```

## Capsicum Sandbox Protection

Prevent debugging sandboxed processes:

```sh
# ctx: after -> applies to object (target process)
mac_abac_ctl rule add "deny debug * -> * ctx:sandboxed=true"
mac_abac_ctl rule add "allow debug * -> *"
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
dtrace -n 'abac:::check-deny { printf("%s -> %s", stringof(arg0), stringof(arg1)); }'

# Measure latency
dtrace -n 'abac:::check-entry { self->ts = timestamp; }
           abac:::check-return /self->ts/ { @["ns"] = quantize(timestamp - self->ts); }'
```

## Policy File

`/etc/mac_abac/policy.conf`:
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
mac_abacd -c /etc/mac_abac/policy.conf
```
