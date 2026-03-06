# vLabel Examples

Comprehensive examples covering all vLabel features.

## Table of Contents

1. [Basic Labeling](#basic-labeling)
2. [Simple Policies](#simple-policies)
3. [Domain Isolation](#domain-isolation)
4. [Sensitivity Levels](#sensitivity-levels)
5. [Jail Integration](#jail-integration)
6. [Capsicum Sandboxing](#capsicum-sandboxing)
7. [Label Transitions](#label-transitions)
8. [Context Constraints](#context-constraints)
9. [Real-World Scenarios](#real-world-scenarios)
10. [Debugging and Monitoring](#debugging-and-monitoring)

---

## Basic Labeling

### Setting Labels on Files

```sh
# Label a single file
setextattr system vlabel "type=trusted" /usr/local/bin/myapp

# Label with multiple attributes
setextattr system vlabel "type=app,domain=web,name=nginx" /usr/local/sbin/nginx

# Using vlabelctl
vlabelctl label set /usr/local/bin/myapp "type=trusted,domain=system"
```

### Labeling Directories of Files

```sh
# Label all binaries in a directory
for f in /usr/local/bin/*; do
    setextattr system vlabel "type=app,domain=user" "$f"
done

# Label system binaries as trusted
for f in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    setextattr system vlabel "type=trusted,domain=system" "$f" 2>/dev/null
done

# Label web application files
find /usr/local/www -type f -exec setextattr system vlabel "type=data,domain=web" {} \;
```

### Viewing Labels

```sh
# Single file
vlabelctl label get /usr/local/bin/myapp
# Output: type=app,domain=web

# Multiple files
for f in /usr/local/bin/*; do
    label=$(getextattr -q system vlabel "$f" 2>/dev/null)
    [ -n "$label" ] && echo "$f: $label"
done

# Find all labeled files
find /usr/local -exec sh -c '
    label=$(getextattr -q system vlabel "$1" 2>/dev/null)
    [ -n "$label" ] && echo "$1: $label"
' _ {} \;
```

### Removing Labels

```sh
# Single file
vlabelctl label remove /path/to/file

# Or using rmextattr
rmextattr system vlabel /path/to/file

# Remove all labels in a directory
find /path/to/dir -exec rmextattr system vlabel {} \; 2>/dev/null
```

---

## Simple Policies

### Block Untrusted Executables

The most basic security policy - prevent execution of untrusted binaries:

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
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# Mark downloads as untrusted
setextattr system vlabel "type=untrusted" /home/user/Downloads/*

# Test
chmod +x /home/user/Downloads/sketch.sh
/home/user/Downloads/sketch.sh
# Result: Permission denied
```

### Allow Only Trusted Executables

Whitelist approach - only explicitly trusted binaries can run:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["exec"],
            "object": { "type": "trusted" }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"]
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["read", "write", "stat", "open", "readdir", "lookup"]
        }
    ]
}
```

Setup:
```sh
# Label all system binaries as trusted
for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    for f in "$dir"/*; do
        [ -x "$f" ] && setextattr system vlabel "type=trusted" "$f"
    done
done
```

### Read-Only System Files

Protect system configuration from modification:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["read", "stat", "open", "lookup"],
            "object": { "type": "system-config" }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["write", "unlink", "rename", "create"],
            "object": { "type": "system-config" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# Label config files
setextattr system vlabel "type=system-config" /etc/passwd
setextattr system vlabel "type=system-config" /etc/master.passwd
setextattr system vlabel "type=system-config" /etc/group
setextattr system vlabel "type=system-config" /etc/rc.conf
```

---

## Domain Isolation

### Web Server Isolation

Restrict web server to only access web-related files:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["read", "write", "open", "stat", "mmap"],
            "subject": { "domain": "web" },
            "object": { "domain": "web" }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read", "open", "stat", "mmap", "exec"],
            "subject": { "domain": "web" },
            "object": { "type": "trusted" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["all"],
            "subject": { "domain": "web" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# Label web server binary
setextattr system vlabel "type=app,domain=web,name=nginx" /usr/local/sbin/nginx

# Label web content
find /usr/local/www -exec setextattr system vlabel "type=data,domain=web" {} \;

# Label web logs
setextattr system vlabel "type=log,domain=web" /var/log/nginx/*

# Label web config
setextattr system vlabel "type=config,domain=web" /usr/local/etc/nginx/*
```

### Database Isolation

Similar pattern for database server:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 10,
            "action": "allow",
            "operations": ["read", "write", "open", "stat", "create", "unlink"],
            "subject": { "domain": "database" },
            "object": { "domain": "database" }
        },
        {
            "id": 11,
            "action": "allow",
            "operations": ["read", "open", "stat", "mmap", "exec"],
            "subject": { "domain": "database" },
            "object": { "type": "trusted" }
        },
        {
            "id": 12,
            "action": "deny",
            "operations": ["all"],
            "subject": { "domain": "database" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# PostgreSQL
setextattr system vlabel "type=app,domain=database,name=postgres" /usr/local/bin/postgres
find /var/db/postgres -exec setextattr system vlabel "type=data,domain=database" {} \;

# MySQL
setextattr system vlabel "type=app,domain=database,name=mysql" /usr/local/libexec/mysqld
find /var/db/mysql -exec setextattr system vlabel "type=data,domain=database" {} \;
```

### Multi-Tenant Isolation

Isolate different customers/tenants:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "tenant-a" },
            "object": { "domain": "tenant-a" }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "tenant-b" },
            "object": { "domain": "tenant-b" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["read", "write", "exec"],
            "subject": { "domain": "tenant-a" },
            "object": { "domain": "tenant-b" }
        },
        {
            "id": 4,
            "action": "deny",
            "operations": ["read", "write", "exec"],
            "subject": { "domain": "tenant-b" },
            "object": { "domain": "tenant-a" }
        },
        {
            "id": 5,
            "action": "allow",
            "operations": ["read", "exec", "stat", "mmap"],
            "object": { "type": "shared" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "trusted" }
        }
    ]
}
```

Setup:
```sh
# Tenant A files
find /home/tenant-a -exec setextattr system vlabel "domain=tenant-a" {} \;

# Tenant B files
find /home/tenant-b -exec setextattr system vlabel "domain=tenant-b" {} \;

# Shared libraries (readable by all)
setextattr system vlabel "type=shared" /lib/*
setextattr system vlabel "type=shared" /usr/lib/*
```

---

## Sensitivity Levels

### Bell-LaPadula Style (No Read Up, No Write Down)

Classic confidentiality model:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "secret" },
            "object": { "level": "secret" }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "secret" },
            "object": { "level": "confidential" }
        },
        {
            "id": 3,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "secret" },
            "object": { "level": "public" }
        },
        {
            "id": 4,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "confidential" },
            "object": { "level": "confidential" }
        },
        {
            "id": 5,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "confidential" },
            "object": { "level": "public" }
        },
        {
            "id": 6,
            "action": "allow",
            "operations": ["read"],
            "subject": { "level": "public" },
            "object": { "level": "public" }
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "public" },
            "object": { "level": "public" }
        },
        {
            "id": 11,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "public" },
            "object": { "level": "confidential" }
        },
        {
            "id": 12,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "public" },
            "object": { "level": "secret" }
        },
        {
            "id": 13,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "confidential" },
            "object": { "level": "confidential" }
        },
        {
            "id": 14,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "confidential" },
            "object": { "level": "secret" }
        },
        {
            "id": 15,
            "action": "allow",
            "operations": ["write"],
            "subject": { "level": "secret" },
            "object": { "level": "secret" }
        },
        {
            "id": 100,
            "action": "deny",
            "operations": ["read", "write"]
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["exec", "stat", "open", "lookup", "readdir"]
        }
    ]
}
```

Setup:
```sh
# Public data
setextattr system vlabel "level=public" /var/www/public/*

# Confidential data
setextattr system vlabel "level=confidential" /var/data/internal/*

# Secret data
setextattr system vlabel "level=secret" /var/data/secret/*

# Label processes based on user clearance (via transition rules)
```

### Simple Integrity Levels

Prevent untrusted data from corrupting trusted files:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["write"],
            "subject": { "level": "low" },
            "object": { "level": "high" }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["write"],
            "subject": { "level": "medium" },
            "object": { "level": "high" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["write"],
            "subject": { "level": "low" },
            "object": { "level": "medium" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Jail Integration

### Host-Only Operations

Restrict certain operations to host system only:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["exec"],
            "object": { "type": "system-admin" },
            "context": { "jail": "host" }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "system-admin" }
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["read", "write"],
            "object": { "type": "host-config" },
            "context": { "jail": "host" }
        },
        {
            "id": 11,
            "action": "deny",
            "operations": ["all"],
            "object": { "type": "host-config" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# Admin tools - host only
setextattr system vlabel "type=system-admin" /usr/sbin/jail
setextattr system vlabel "type=system-admin" /usr/sbin/jexec
setextattr system vlabel "type=system-admin" /sbin/mount
setextattr system vlabel "type=system-admin" /sbin/zpool
setextattr system vlabel "type=system-admin" /sbin/zfs

# Host config - host only
setextattr system vlabel "type=host-config" /etc/rc.conf
setextattr system vlabel "type=host-config" /boot/loader.conf
```

### Per-Jail Isolation

Different rules for different jails:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "jail-web" },
            "object": { "domain": "jail-web" },
            "context": { "jail": 1 }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "jail-db" },
            "object": { "domain": "jail-db" },
            "context": { "jail": 2 }
        },
        {
            "id": 3,
            "action": "allow",
            "operations": ["read"],
            "subject": { "domain": "jail-web" },
            "object": { "domain": "shared-libs" }
        },
        {
            "id": 4,
            "action": "allow",
            "operations": ["read"],
            "subject": { "domain": "jail-db" },
            "object": { "domain": "shared-libs" }
        },
        {
            "id": 10,
            "action": "deny",
            "operations": ["all"],
            "context": { "jail": "any" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"],
            "context": { "jail": "host" }
        }
    ]
}
```

### Jail Breakout Prevention

Extra protection against jail escape attempts:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec", "read", "write"],
            "object": { "type": "host-only" },
            "context": { "jail": "any" }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["chdir"],
            "object": { "type": "host-root" },
            "context": { "jail": "any" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["mmap"],
            "object": { "type": "kernel-module" },
            "context": { "jail": "any" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Capsicum Sandboxing

### Sandboxed Process Restrictions

Restrict what sandboxed (capability mode) processes can access:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["read"],
            "object": { "type": "sandbox-allowed" },
            "context": { "sandboxed": true }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "context": { "sandboxed": true }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["write"],
            "object": { "type": "system" },
            "context": { "sandboxed": true }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

### Defense in Depth with Capsicum

Combine Capsicum and vLabel for layered security:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["read", "write"],
            "subject": { "domain": "sandbox" },
            "object": { "domain": "sandbox" },
            "context": { "sandboxed": true }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["all"],
            "subject": { "domain": "sandbox" },
            "context": { "sandboxed": false }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["exec", "mmap"],
            "context": { "sandboxed": true }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

### Pre-Sandbox vs Post-Sandbox

Different rules before and after entering capability mode:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["all"],
            "subject": { "name": "myapp" },
            "context": { "sandboxed": false }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read", "write"],
            "subject": { "name": "myapp" },
            "object": { "name": "myapp-data" },
            "context": { "sandboxed": true }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["all"],
            "subject": { "name": "myapp" },
            "context": { "sandboxed": true }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Label Transitions

### Basic Privilege Escalation

Transition to privileged label when running su/sudo:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "setuid", "name": "su" },
            "newlabel": "type=privileged,domain=system"
        },
        {
            "id": 2,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "setuid", "name": "sudo" },
            "newlabel": "type=privileged,domain=system"
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "privileged" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
setextattr system vlabel "type=setuid,name=su" /usr/bin/su
setextattr system vlabel "type=setuid,name=sudo" /usr/local/bin/sudo
```

### Domain Entry Points

Transition into application domains:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "entrypoint", "domain": "web" },
            "newlabel": "type=app,domain=web"
        },
        {
            "id": 2,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "entrypoint", "domain": "database" },
            "newlabel": "type=app,domain=database"
        },
        {
            "id": 3,
            "action": "transition",
            "operations": ["exec"],
            "object": { "type": "entrypoint", "domain": "mail" },
            "newlabel": "type=app,domain=mail"
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "web" },
            "object": { "domain": "web" }
        },
        {
            "id": 11,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "database" },
            "object": { "domain": "database" }
        },
        {
            "id": 12,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "mail" },
            "object": { "domain": "mail" }
        },
        {
            "id": 100,
            "action": "deny",
            "operations": ["write"],
            "subject": { "domain": "web" }
        },
        {
            "id": 101,
            "action": "deny",
            "operations": ["write"],
            "subject": { "domain": "database" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Setup:
```sh
# Entry points
setextattr system vlabel "type=entrypoint,domain=web" /usr/local/sbin/nginx
setextattr system vlabel "type=entrypoint,domain=database" /usr/local/bin/postgres
setextattr system vlabel "type=entrypoint,domain=mail" /usr/local/libexec/dovecot/dovecot
```

### Conditional Transitions

Transition only from specific source labels:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "transition",
            "operations": ["exec"],
            "subject": { "type": "user" },
            "object": { "type": "setuid", "name": "su" },
            "newlabel": "type=privileged,domain=system"
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "subject": { "type": "untrusted" },
            "object": { "type": "setuid" }
        },
        {
            "id": 3,
            "action": "transition",
            "operations": ["exec"],
            "subject": { "type": "admin" },
            "object": { "type": "setuid", "name": "su" },
            "newlabel": "type=root,domain=system"
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

### Dropping Privileges

Transition to less privileged label:

```json
{
    "mode": "enforcing",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "transition",
            "operations": ["exec"],
            "subject": { "type": "privileged" },
            "object": { "type": "dropper", "name": "drop-privs" },
            "newlabel": "type=user,domain=restricted"
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "subject": { "type": "restricted" },
            "object": { "type": "setuid" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Context Constraints

### UID-Based Rules

Different rules for different users:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["all"],
            "context": { "uid": 0 }
        },
        {
            "id": 2,
            "action": "allow",
            "operations": ["read", "exec"],
            "object": { "type": "public" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["write"],
            "object": { "type": "system" },
            "context": { "uid": 1000 }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

### TTY Requirement

Require controlling terminal for sensitive operations:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["exec"],
            "object": { "type": "interactive" },
            "context": { "tty": true }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "interactive" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

### Combined Constraints

Multiple context requirements:

```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "allow",
            "operations": ["exec"],
            "object": { "type": "admin-tool" },
            "context": {
                "jail": "host",
                "uid": 0,
                "tty": true
            }
        },
        {
            "id": 2,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "admin-tool" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Real-World Scenarios

### Web Hosting Server

Complete policy for a web hosting environment:

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
            "id": 10,
            "action": "allow",
            "operations": ["read", "write", "open", "stat", "readdir"],
            "subject": { "domain": "web" },
            "object": { "domain": "web" }
        },
        {
            "id": 11,
            "action": "allow",
            "operations": ["read", "open", "stat", "mmap"],
            "subject": { "domain": "web" },
            "object": { "type": "shared-lib" }
        },
        {
            "id": 12,
            "action": "deny",
            "operations": ["read", "write"],
            "subject": { "domain": "web" },
            "object": { "domain": "database" }
        },
        {
            "id": 20,
            "action": "allow",
            "operations": ["read", "write", "open", "stat", "create", "unlink"],
            "subject": { "domain": "database" },
            "object": { "domain": "database" }
        },
        {
            "id": 21,
            "action": "deny",
            "operations": ["read", "write"],
            "subject": { "domain": "database" },
            "object": { "domain": "web" }
        },
        {
            "id": 30,
            "action": "deny",
            "operations": ["all"],
            "object": { "type": "host-only" },
            "context": { "jail": "any" }
        },
        {
            "id": 100,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "trusted" },
            "context": { "jail": "host" }
        },
        {
            "id": 999,
            "action": "deny",
            "operations": ["all"]
        }
    ]
}
```

Labeling script:
```sh
#!/bin/sh

# System binaries
for f in /bin/* /sbin/* /usr/bin/* /usr/sbin/*; do
    setextattr system vlabel "type=trusted" "$f" 2>/dev/null
done

# Shared libraries
find /lib /usr/lib -name '*.so*' -exec setextattr system vlabel "type=shared-lib" {} \;

# Web server
setextattr system vlabel "type=app,domain=web" /usr/local/sbin/nginx
find /usr/local/www -exec setextattr system vlabel "type=data,domain=web" {} \;
find /var/log/nginx -exec setextattr system vlabel "type=log,domain=web" {} \;

# Database
setextattr system vlabel "type=app,domain=database" /usr/local/bin/postgres
find /var/db/postgres -exec setextattr system vlabel "type=data,domain=database" {} \;

# Host-only
setextattr system vlabel "type=host-only" /etc/rc.conf
setextattr system vlabel "type=host-only" /boot/loader.conf
```

### Development Workstation

Policy for a developer workstation:

```json
{
    "mode": "permissive",
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
            "action": "deny",
            "operations": ["write", "unlink"],
            "object": { "type": "system-critical" }
        },
        {
            "id": 3,
            "action": "deny",
            "operations": ["read"],
            "object": { "level": "secret" },
            "subject": { "level": "public", "negate": true }
        },
        {
            "id": 10,
            "action": "allow",
            "operations": ["all"],
            "subject": { "domain": "development" },
            "object": { "domain": "development" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

---

## Debugging and Monitoring

### Enable Verbose Auditing

```sh
# Set verbose audit level
sysctl security.mac.vlabel.audit_level=3

# Or via vlabelctl
vlabelctl audit verbose
```

### Monitor in Real-Time

```sh
# Watch all decisions
vlabelctl monitor

# Output:
# [14:30:01] ALLOW op=0x0001 pid=1234 uid=0 subj=type=trusted obj=type=system path=/bin/ls
# [14:30:02] DENY op=0x0001 pid=1235 uid=1000 subj=type=user obj=type=untrusted path=/tmp/bad
```

### Check Statistics

```sh
# View stats
vlabelctl stats

# Or via sysctl
sysctl security.mac.vlabel
```

### Test Policy Without Enforcing

```sh
# Set permissive mode
sysctl security.mac.vlabel.mode=1

# Run your tests - denials are logged but not enforced

# Check audit log
vlabelctl monitor

# When satisfied, enable enforcement
sysctl security.mac.vlabel.mode=2
```

### Validate Policy Syntax

```sh
# Test before loading
vlabeld -t -v -c /path/to/policy.conf

# Output shows each rule parsed
```

### Debug Label Reading

```sh
# Check if label is set
getextattr system vlabel /path/to/file

# Check kernel stats for label reads
sysctl security.mac.vlabel.labels_read
sysctl security.mac.vlabel.labels_default
```

### Trace Specific Operations

Create a targeted policy to trace specific access:

```json
{
    "mode": "permissive",
    "audit": "decisions",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "name": "target-app" }
        },
        {
            "id": 1000,
            "action": "allow",
            "operations": ["all"]
        }
    ]
}
```

Then watch:
```sh
vlabelctl monitor | grep target-app
```
