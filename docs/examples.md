# vLabel Examples

Comprehensive examples covering all vLabel features with the flexible key-value label system.

## Table of Contents

1. [Label Format Overview](#label-format-overview)
2. [Basic Labeling](#basic-labeling)
3. [Pattern Matching](#pattern-matching)
4. [Simple Policies](#simple-policies)
5. [Domain Isolation](#domain-isolation)
6. [Sensitivity and Compartments](#sensitivity-and-compartments)
7. [Jail Integration](#jail-integration)
8. [Capsicum Sandboxing](#capsicum-sandboxing)
9. [Label Transitions](#label-transitions)
10. [Context Constraints](#context-constraints)
11. [Complex Real-World Scenarios](#complex-real-world-scenarios)
12. [Debugging and Monitoring](#debugging-and-monitoring)
13. [Advanced Pattern Examples](#advanced-pattern-examples)

---

## Label Format Overview

vLabel uses a flexible key-value pair format for labels. Labels can contain **any** attributes you define - there are no hardcoded fields.

### Label String Format

**Command line** (comma-separated for convenience):
```
key1=value1,key2=value2,key3=value3
```

**Storage format** (newline-separated in extended attributes):
```
key1=value1
key2=value2
key3=value3
```

The `vlabelctl` tool automatically converts between formats.

### Examples of Labels

```sh
# Simple type label
type=trusted

# Multiple attributes
type=app,domain=web,name=nginx

# Security classification
sensitivity=secret,compartment=hr,project=alpha

# Complex multi-attribute label
type=daemon,domain=database,name=postgres,env=production,tenant=acme,clearance=high

# Custom application-specific attributes
role=frontend,tier=presentation,version=2.1,region=us-west
```

### System Limits

#### Per-Label Limits

These limits apply to each individual label (on files or in rule patterns):

| Constraint | Value | Notes |
|------------|-------|-------|
| Maximum label length | 12,288 bytes (12KB) | Total string length |
| Maximum key length | 63 bytes | Per key name |
| Maximum value length | 255 bytes | Per value |
| Maximum key-value pairs | 32 | Per label |

#### System-Wide Limits

These limits apply to the kernel rule engine:

| Constraint | Value | Notes |
|------------|-------|-------|
| Maximum rules | 1,024 | Total rules loaded in kernel |

#### What This Means

- **A single file** can have a label with up to 32 key=value pairs
- **A single rule** has subject and object patterns, each can have up to 32 pairs
- **The kernel** can hold up to 1,024 rules total
- **Each process** has a credential label (also up to 32 pairs)

#### Validation

Both the kernel and `vlabelctl` validate these limits:
- Labels exceeding limits are rejected with an error
- Rules with invalid patterns are rejected when adding

---

## Basic Labeling

### Setting Labels on Files

```sh
# Simple label
vlabelctl label set /usr/local/bin/myapp "type=trusted"

# Multiple attributes
vlabelctl label set /usr/local/sbin/nginx "type=app,domain=web,name=nginx"

# Complex security label
vlabelctl label set /var/data/hr/salaries.db \
    "type=data,sensitivity=confidential,compartment=hr,owner=hr-dept"

# Using setextattr directly
setextattr system vlabel "type=trusted,domain=system" /usr/local/bin/myapp
```

### Labeling with Custom Attributes

```sh
# Application-specific labels
vlabelctl label set /opt/myapp/bin/server \
    "app=myapp,component=server,env=production,version=3.2"

# Multi-tenant labels
vlabelctl label set /data/tenant-acme/uploads \
    "tenant=acme,type=upload,sensitivity=internal"

# Project-based labels
vlabelctl label set /projects/apollo/src \
    "project=apollo,clearance=topsecret,compartment=sci,need-to-know=true"
```

### Labeling Directories of Files

```sh
# Label all files with tenant identifier
for f in /data/tenant-acme/*; do
    setextattr system vlabel "tenant=acme,type=data" "$f"
done

# Label with environment attribute
find /opt/production -type f -exec \
    setextattr system vlabel "env=production,type=app" {} \;

# Label with multiple security attributes
find /var/classified -type f -exec \
    setextattr system vlabel "sensitivity=secret,compartment=defense,handling=noforn" {} \;
```

### Viewing Labels

```sh
# Single file
vlabelctl label get /usr/local/bin/myapp
# Output: type=app,domain=web,name=nginx,env=production

# Parse specific attributes from label
label=$(vlabelctl label get /path/to/file)
echo "$label" | tr ',' '\n' | grep "^sensitivity="
# Output: sensitivity=secret

# Find all files with specific label attributes
find /data -exec sh -c '
    label=$(getextattr -q system vlabel "$1" 2>/dev/null)
    case "$label" in
        *sensitivity=secret*) echo "$1: $label" ;;
    esac
' _ {} \;
```

---

## Pattern Matching

Patterns match against labels using key=value pairs. All specified pairs must match (AND logic).

### Pattern Syntax

| Pattern | Meaning |
|---------|---------|
| `*` | Match any label (wildcard) |
| `key=value` | Label must have exact key=value |
| `key=*` | Label must have key (any value) |
| `key1=val1,key2=val2` | Must have BOTH pairs |
| `!pattern` | Negate the match |

### Pattern Examples

```sh
# Match anything
*

# Match labels with type=app
type=app

# Match labels with both type=app AND domain=web
type=app,domain=web

# Match any label that has a sensitivity key
sensitivity=*

# Match labels that do NOT have type=untrusted
!type=untrusted

# Match labels with sensitivity=secret but NOT compartment=hr
# (requires two rules - one allow, one deny)

# Complex: match production database servers
type=daemon,domain=database,env=production

# Match any label with tenant=acme
tenant=acme

# Match by multiple custom attributes
project=apollo,clearance=topsecret,need-to-know=true
```

### Testing Pattern Matches

```sh
# Test if an operation would be allowed
vlabelctl test exec "type=user,domain=staff" "type=app,domain=web"

# Test with complex labels
vlabelctl test read \
    "role=analyst,clearance=secret,compartment=intel" \
    "sensitivity=secret,compartment=intel,project=alpha"
```

---

## Simple Policies

### Block Untrusted Executables

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    {
        id = 1;
        action = "deny";
        operations = ["exec"];
        object = { type = "untrusted"; };
    },
    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

### Allow Only Labeled Executables

Whitelist approach - unlabeled files cannot execute:

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    {
        id = 1;
        action = "allow";
        operations = ["exec"];
        object = { type = "trusted"; };
    },
    {
        id = 2;
        action = "allow";
        operations = ["exec"];
        object = { type = "app"; };
    },
    {
        id = 3;
        action = "deny";
        operations = ["exec"];
        # No object pattern = match all
    },
    {
        id = 1000;
        action = "allow";
        operations = ["read", "write", "stat", "open", "readdir", "lookup"];
    }
];
```

---

## Domain Isolation

### Multi-Service Isolation

Isolate web, database, and cache services from each other:

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Web service - only access web domain files
    {
        id = 10;
        action = "allow";
        operations = ["read", "write", "open", "stat", "mmap"];
        subject = { domain = "web"; };
        object = { domain = "web"; };
    },

    # Database service - only access database domain files
    {
        id = 20;
        action = "allow";
        operations = ["read", "write", "open", "stat", "create", "unlink"];
        subject = { domain = "database"; };
        object = { domain = "database"; };
    },

    # Cache service - only access cache domain files
    {
        id = 30;
        action = "allow";
        operations = ["read", "write", "open", "stat"];
        subject = { domain = "cache"; };
        object = { domain = "cache"; };
    },

    # All services can read shared libraries
    {
        id = 100;
        action = "allow";
        operations = ["read", "open", "stat", "mmap", "exec"];
        object = { type = "shared"; };
    },

    # Deny cross-domain access
    {
        id = 200;
        action = "deny";
        operations = ["read", "write"];
        subject = { domain = "web"; };
        object = { domain = "database"; };
    },
    {
        id = 201;
        action = "deny";
        operations = ["read", "write"];
        subject = { domain = "database"; };
        object = { domain = "web"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

Setup:
```sh
# Web service
setextattr system vlabel "type=app,domain=web,name=nginx" /usr/local/sbin/nginx
find /usr/local/www -exec setextattr system vlabel "type=data,domain=web" {} \;
find /var/log/nginx -exec setextattr system vlabel "type=log,domain=web" {} \;

# Database service
setextattr system vlabel "type=app,domain=database,name=postgres" /usr/local/bin/postgres
find /var/db/postgres -exec setextattr system vlabel "type=data,domain=database" {} \;

# Cache service
setextattr system vlabel "type=app,domain=cache,name=redis" /usr/local/bin/redis-server
find /var/db/redis -exec setextattr system vlabel "type=data,domain=cache" {} \;

# Shared libraries
find /lib /usr/lib /usr/local/lib -name '*.so*' \
    -exec setextattr system vlabel "type=shared" {} \;
```

### Multi-Tenant Isolation

Complete tenant isolation with shared infrastructure:

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Tenant A - full access to own data
    {
        id = 10;
        action = "allow";
        operations = ["all"];
        subject = { tenant = "acme"; };
        object = { tenant = "acme"; };
    },

    # Tenant B - full access to own data
    {
        id = 20;
        action = "allow";
        operations = ["all"];
        subject = { tenant = "globex"; };
        object = { tenant = "globex"; };
    },

    # Tenant C - full access to own data
    {
        id = 30;
        action = "allow";
        operations = ["all"];
        subject = { tenant = "initech"; };
        object = { tenant = "initech"; };
    },

    # Cross-tenant access denied
    {
        id = 100;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "acme"; };
        object = { tenant = "globex"; };
    },
    {
        id = 101;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "acme"; };
        object = { tenant = "initech"; };
    },
    {
        id = 102;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "globex"; };
        object = { tenant = "acme"; };
    },
    {
        id = 103;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "globex"; };
        object = { tenant = "initech"; };
    },
    {
        id = 104;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "initech"; };
        object = { tenant = "acme"; };
    },
    {
        id = 105;
        action = "deny";
        operations = ["read", "write", "exec"];
        subject = { tenant = "initech"; };
        object = { tenant = "globex"; };
    },

    # All tenants can access shared platform resources
    {
        id = 500;
        action = "allow";
        operations = ["read", "exec", "mmap", "stat"];
        object = { type = "platform"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
        subject = { type = "platform"; };
    }
];
```

---

## Sensitivity and Compartments

### Multi-Level Security with Compartments

Implement classification levels with compartmentalized access:

```ucl
mode = "enforcing";
audit = "decisions";

rules = [
    # Top Secret with SCI compartment - most restricted
    {
        id = 1;
        action = "allow";
        operations = ["read"];
        subject = "clearance=topsecret,compartment=sci";
        object = "sensitivity=topsecret,compartment=sci";
    },

    # Top Secret general - can read TS and below
    {
        id = 10;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { sensitivity = "topsecret"; };
    },
    {
        id = 11;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { sensitivity = "secret"; };
    },
    {
        id = 12;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { sensitivity = "confidential"; };
    },
    {
        id = 13;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { sensitivity = "unclassified"; };
    },

    # Secret clearance - can read Secret and below
    {
        id = 20;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { sensitivity = "secret"; };
    },
    {
        id = 21;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { sensitivity = "confidential"; };
    },
    {
        id = 22;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { sensitivity = "unclassified"; };
    },

    # Confidential clearance
    {
        id = 30;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "confidential"; };
        object = { sensitivity = "confidential"; };
    },
    {
        id = 31;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "confidential"; };
        object = { sensitivity = "unclassified"; };
    },

    # Unclassified - only unclassified data
    {
        id = 40;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "unclassified"; };
        object = { sensitivity = "unclassified"; };
    },

    # Deny read-up (implicit with first-match, but explicit is clearer)
    {
        id = 100;
        action = "deny";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { sensitivity = "topsecret"; };
    },
    {
        id = 101;
        action = "deny";
        operations = ["read"];
        subject = { clearance = "confidential"; };
        object = { sensitivity = "secret"; };
    },

    # Write rules - no write-down (Bell-LaPadula)
    {
        id = 200;
        action = "allow";
        operations = ["write"];
        subject = { clearance = "unclassified"; };
        object = { sensitivity = "unclassified"; };
    },
    {
        id = 201;
        action = "allow";
        operations = ["write"];
        subject = { clearance = "unclassified"; };
        object = { sensitivity = "confidential"; };
    },
    {
        id = 202;
        action = "allow";
        operations = ["write"];
        subject = { clearance = "unclassified"; };
        object = { sensitivity = "secret"; };
    },
    # ... continue pattern for write-up only

    {
        id = 1000;
        action = "allow";
        operations = ["exec", "stat", "open", "lookup", "readdir", "mmap"];
    }
];
```

Setup:
```sh
# Classify data by sensitivity and compartment
setextattr system vlabel "sensitivity=topsecret,compartment=sci,project=blackbird" \
    /data/classified/sci/blackbird/*

setextattr system vlabel "sensitivity=secret,compartment=intel" \
    /data/classified/intel/*

setextattr system vlabel "sensitivity=confidential,compartment=hr" \
    /data/hr/personnel/*

setextattr system vlabel "sensitivity=unclassified" \
    /data/public/*
```

### Department-Based Compartmentalization

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # HR department - access HR data
    {
        id = 10;
        action = "allow";
        operations = ["read", "write"];
        subject = { department = "hr"; };
        object = { compartment = "hr"; };
    },

    # Finance department - access finance data
    {
        id = 20;
        action = "allow";
        operations = ["read", "write"];
        subject = { department = "finance"; };
        object = { compartment = "finance"; };
    },

    # Engineering department
    {
        id = 30;
        action = "allow";
        operations = ["read", "write"];
        subject = { department = "engineering"; };
        object = { compartment = "engineering"; };
    },

    # Legal can read HR and Finance (audit purposes)
    {
        id = 40;
        action = "allow";
        operations = ["read"];
        subject = { department = "legal"; };
        object = { compartment = "hr"; };
    },
    {
        id = 41;
        action = "allow";
        operations = ["read"];
        subject = { department = "legal"; };
        object = { compartment = "finance"; };
    },

    # Executives can read everything
    {
        id = 50;
        action = "allow";
        operations = ["read"];
        subject = { role = "executive"; };
    },

    # Deny cross-department writes
    {
        id = 100;
        action = "deny";
        operations = ["write"];
        subject = { department = "hr"; };
        object = { compartment = "finance"; };
    },
    {
        id = 101;
        action = "deny";
        operations = ["write"];
        subject = { department = "finance"; };
        object = { compartment = "hr"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

---

## Jail Integration

### Per-Jail Service Isolation

Different services in different jails with strict isolation:

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Web jail (jail ID 1) - web service
    {
        id = 10;
        action = "allow";
        operations = ["read", "write", "open", "stat"];
        subject = { service = "web"; };
        object = { service = "web"; };
        context = { jail = 1; };
    },

    # Database jail (jail ID 2) - database service
    {
        id = 20;
        action = "allow";
        operations = ["read", "write", "open", "stat", "create", "unlink"];
        subject = { service = "database"; };
        object = { service = "database"; };
        context = { jail = 2; };
    },

    # Mail jail (jail ID 3) - mail service
    {
        id = 30;
        action = "allow";
        operations = ["read", "write", "open", "stat"];
        subject = { service = "mail"; };
        object = { service = "mail"; };
        context = { jail = 3; };
    },

    # Shared resources readable from any jail
    {
        id = 100;
        action = "allow";
        operations = ["read", "exec", "mmap", "stat"];
        object = { type = "shared"; };
    },

    # Deny jails from accessing host-only resources
    {
        id = 200;
        action = "deny";
        operations = ["all"];
        object = { scope = "host-only"; };
        context = { jail = "any"; };
    },

    # Host has full access
    {
        id = 1000;
        action = "allow";
        operations = ["all"];
        context = { jail = "host"; };
    }
];
```

### Jail Escape Prevention

Extra protection layer against jail escapes:

```ucl
mode = "enforcing";
audit = "verbose";

rules = [
    # Block access to host filesystem markers
    {
        id = 1;
        action = "deny";
        operations = ["read", "write", "exec", "chdir"];
        object = { location = "host-root"; };
        context = { jail = "any"; };
    },

    # Block access to kernel interfaces
    {
        id = 2;
        action = "deny";
        operations = ["read", "write", "open"];
        object = { type = "kernel-interface"; };
        context = { jail = "any"; };
    },

    # Block loading kernel modules
    {
        id = 3;
        action = "deny";
        operations = ["exec", "mmap"];
        object = { type = "kernel-module"; };
        context = { jail = "any"; };
    },

    # Block access to jail management tools
    {
        id = 4;
        action = "deny";
        operations = ["exec"];
        object = { type = "jail-admin"; };
        context = { jail = "any"; };
    },

    # Block access to host network config
    {
        id = 5;
        action = "deny";
        operations = ["read", "write"];
        object = { type = "network-config"; scope = "host"; };
        context = { jail = "any"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

Setup:
```sh
# Mark host-only resources
setextattr system vlabel "location=host-root" /
setextattr system vlabel "type=kernel-interface" /dev/mem
setextattr system vlabel "type=kernel-interface" /dev/kmem
setextattr system vlabel "type=kernel-module" /boot/kernel/*.ko
setextattr system vlabel "type=jail-admin" /usr/sbin/jail
setextattr system vlabel "type=jail-admin" /usr/sbin/jexec
setextattr system vlabel "type=network-config,scope=host" /etc/rc.conf
setextattr system vlabel "type=network-config,scope=host" /etc/pf.conf
```

---

## Capsicum Sandboxing

### Sandbox-Aware Policies

Different rules for sandboxed vs non-sandboxed processes:

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Before sandboxing - app can initialize
    {
        id = 10;
        action = "allow";
        operations = ["all"];
        subject = { app = "imageprocessor"; };
        context = { sandboxed = false; };
    },

    # After sandboxing - restricted to specific files
    {
        id = 20;
        action = "allow";
        operations = ["read"];
        subject = { app = "imageprocessor"; };
        object = { type = "input-image"; };
        context = { sandboxed = true; };
    },
    {
        id = 21;
        action = "allow";
        operations = ["write"];
        subject = { app = "imageprocessor"; };
        object = { type = "output-image"; };
        context = { sandboxed = true; };
    },
    {
        id = 22;
        action = "allow";
        operations = ["read", "mmap"];
        subject = { app = "imageprocessor"; };
        object = { type = "library"; };
        context = { sandboxed = true; };
    },

    # Deny everything else when sandboxed
    {
        id = 100;
        action = "deny";
        operations = ["all"];
        subject = { app = "imageprocessor"; };
        context = { sandboxed = true; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

### Defense in Depth

Combine Capsicum with vLabel for multiple security layers:

```ucl
mode = "enforcing";
audit = "decisions";

rules = [
    # Sandboxed network service - very restricted
    {
        id = 10;
        action = "allow";
        operations = ["read", "write"];
        subject = "app=netservice,sandbox-level=high";
        object = "type=socket-buffer";
        context = { sandboxed = true; };
    },

    # Sandboxed file processor
    {
        id = 20;
        action = "allow";
        operations = ["read"];
        subject = "app=fileproc,sandbox-level=medium";
        object = "type=input-file";
        context = { sandboxed = true; };
    },
    {
        id = 21;
        action = "allow";
        operations = ["write"];
        subject = "app=fileproc,sandbox-level=medium";
        object = "type=output-file";
        context = { sandboxed = true; };
    },

    # No exec when sandboxed
    {
        id = 100;
        action = "deny";
        operations = ["exec"];
        context = { sandboxed = true; };
    },

    # No access to credentials when sandboxed
    {
        id = 101;
        action = "deny";
        operations = ["read"];
        object = { type = "credential"; };
        context = { sandboxed = true; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

---

## Label Transitions

### Application Domain Entry Points

Transition processes into restricted domains when they exec specific binaries:

```ucl
mode = "enforcing";
audit = "decisions";

rules = [
    # Transition into web domain when starting nginx
    {
        id = 1;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,domain=web,app=nginx";
        newlabel = "type=daemon,domain=web,app=nginx,restricted=true";
    },

    # Transition into database domain when starting postgres
    {
        id = 2;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,domain=database,app=postgres";
        newlabel = "type=daemon,domain=database,app=postgres,restricted=true";
    },

    # Transition into mail domain
    {
        id = 3;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,domain=mail,app=postfix";
        newlabel = "type=daemon,domain=mail,app=postfix,restricted=true";
    },

    # Once in restricted domain, enforce isolation
    {
        id = 100;
        action = "allow";
        operations = ["all"];
        subject = { domain = "web"; restricted = "true"; };
        object = { domain = "web"; };
    },
    {
        id = 101;
        action = "deny";
        operations = ["read", "write"];
        subject = { domain = "web"; restricted = "true"; };
        # Deny access to anything not in web domain
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

### Privilege Escalation Control

Controlled transitions for setuid binaries:

```ucl
mode = "enforcing";
audit = "decisions";

rules = [
    # Normal user executing su -> become privileged
    {
        id = 1;
        action = "transition";
        operations = ["exec"];
        subject = { role = "user"; };
        object = "type=setuid,name=su";
        newlabel = "role=privileged,domain=system,escalated=true";
    },

    # Admin executing su -> become root
    {
        id = 2;
        action = "transition";
        operations = ["exec"];
        subject = { role = "admin"; };
        object = "type=setuid,name=su";
        newlabel = "role=root,domain=system";
    },

    # Block untrusted from setuid
    {
        id = 3;
        action = "deny";
        operations = ["exec"];
        subject = { trust = "untrusted"; };
        object = { type = "setuid"; };
    },

    # Transition for sudo with audit trail
    {
        id = 10;
        action = "transition";
        operations = ["exec"];
        object = "type=setuid,name=sudo";
        newlabel = "role=elevated,via=sudo,audit=required";
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

### Privilege De-escalation

Drop privileges when entering sandboxed mode:

```ucl
mode = "enforcing";
audit = "decisions";

rules = [
    # Service starting - full privileges
    {
        id = 1;
        action = "allow";
        operations = ["all"];
        subject = { role = "service-init"; };
    },

    # After initialization, service execs worker with dropped privs
    {
        id = 2;
        action = "transition";
        operations = ["exec"];
        subject = { role = "service-init"; };
        object = "type=service-worker";
        newlabel = "role=worker,privileges=dropped,sandbox=required";
    },

    # Workers with dropped privileges are restricted
    {
        id = 10;
        action = "allow";
        operations = ["read", "write"];
        subject = { role = "worker"; privileges = "dropped"; };
        object = { type = "work-data"; };
    },
    {
        id = 11;
        action = "deny";
        operations = ["exec"];
        subject = { role = "worker"; privileges = "dropped"; };
    },
    {
        id = 12;
        action = "deny";
        operations = ["all"];
        subject = { role = "worker"; privileges = "dropped"; };
        object = { type = "config"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

---

## Context Constraints

### UID-Based Access Control

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Root can do anything
    {
        id = 1;
        action = "allow";
        operations = ["all"];
        context = { uid = 0; };
    },

    # Wheel group member (uid 1001) - admin access
    {
        id = 10;
        action = "allow";
        operations = ["read", "write"];
        object = { type = "admin-config"; };
        context = { uid = 1001; };
    },

    # Service account (uid 65534/nobody) - very restricted
    {
        id = 20;
        action = "allow";
        operations = ["read"];
        object = { type = "public"; };
        context = { uid = 65534; };
    },
    {
        id = 21;
        action = "deny";
        operations = ["write", "exec"];
        context = { uid = 65534; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

### Interactive Session Requirements

```ucl
mode = "enforcing";
audit = "denials";

rules = [
    # Dangerous admin commands require TTY
    {
        id = 1;
        action = "allow";
        operations = ["exec"];
        object = { type = "dangerous-admin"; };
        context = { tty = true; jail = "host"; uid = 0; };
    },
    {
        id = 2;
        action = "deny";
        operations = ["exec"];
        object = { type = "dangerous-admin"; };
    },

    # Password changes require TTY
    {
        id = 10;
        action = "allow";
        operations = ["exec"];
        object = { name = "passwd"; };
        context = { tty = true; };
    },
    {
        id = 11;
        action = "deny";
        operations = ["exec"];
        object = { name = "passwd"; };
    },

    {
        id = 1000;
        action = "allow";
        operations = ["all"];
    }
];
```

Setup:
```sh
setextattr system vlabel "type=dangerous-admin" /sbin/shutdown
setextattr system vlabel "type=dangerous-admin" /sbin/reboot
setextattr system vlabel "type=dangerous-admin" /sbin/halt
setextattr system vlabel "type=dangerous-admin" /sbin/init
setextattr system vlabel "name=passwd" /usr/bin/passwd
```

---

## Complex Real-World Scenarios

### Enterprise Web Application Stack

Complete policy for a production web application:

```ucl
# Production Web Stack Policy
# Nginx -> PHP-FPM -> PostgreSQL

mode = "enforcing";
audit = "denials";

rules = [
    # === NGINX (Web Frontend) ===
    {
        id = 100;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,app=nginx";
        newlabel = "layer=frontend,app=nginx,env=production";
    },
    {
        id = 101;
        action = "allow";
        operations = ["read", "stat", "open"];
        subject = { layer = "frontend"; app = "nginx"; };
        object = { type = "static-content"; };
    },
    {
        id = 102;
        action = "allow";
        operations = ["read", "write"];
        subject = { layer = "frontend"; app = "nginx"; };
        object = { type = "nginx-cache"; };
    },
    {
        id = 103;
        action = "allow";
        operations = ["write"];
        subject = { layer = "frontend"; app = "nginx"; };
        object = { type = "nginx-log"; };
    },

    # === PHP-FPM (Application Layer) ===
    {
        id = 200;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,app=php-fpm";
        newlabel = "layer=application,app=php-fpm,env=production";
    },
    {
        id = 201;
        action = "allow";
        operations = ["read", "stat"];
        subject = { layer = "application"; app = "php-fpm"; };
        object = { type = "php-code"; };
    },
    {
        id = 202;
        action = "allow";
        operations = ["read", "write"];
        subject = { layer = "application"; app = "php-fpm"; };
        object = { type = "session-data"; };
    },
    {
        id = 203;
        action = "allow";
        operations = ["read", "write"];
        subject = { layer = "application"; app = "php-fpm"; };
        object = { type = "upload-tmp"; };
    },

    # === POSTGRESQL (Database Layer) ===
    {
        id = 300;
        action = "transition";
        operations = ["exec"];
        object = "type=entrypoint,app=postgres";
        newlabel = "layer=database,app=postgres,env=production";
    },
    {
        id = 301;
        action = "allow";
        operations = ["read", "write", "create", "unlink"];
        subject = { layer = "database"; app = "postgres"; };
        object = { type = "postgres-data"; };
    },
    {
        id = 302;
        action = "allow";
        operations = ["read"];
        subject = { layer = "database"; app = "postgres"; };
        object = { type = "postgres-config"; };
    },
    {
        id = 303;
        action = "allow";
        operations = ["write"];
        subject = { layer = "database"; app = "postgres"; };
        object = { type = "postgres-log"; };
    },

    # === CROSS-LAYER RESTRICTIONS ===
    # Frontend cannot access database directly
    {
        id = 400;
        action = "deny";
        operations = ["read", "write"];
        subject = { layer = "frontend"; };
        object = { layer = "database"; };
    },
    # Application cannot modify static content
    {
        id = 401;
        action = "deny";
        operations = ["write", "unlink"];
        subject = { layer = "application"; };
        object = { type = "static-content"; };
    },
    # Database isolated from web layers
    {
        id = 402;
        action = "deny";
        operations = ["read", "write"];
        subject = { layer = "database"; };
        object = { layer = "frontend"; };
    },
    {
        id = 403;
        action = "deny";
        operations = ["read", "write"];
        subject = { layer = "database"; };
        object = { layer = "application"; };
    },

    # === SHARED RESOURCES ===
    {
        id = 500;
        action = "allow";
        operations = ["read", "exec", "mmap"];
        object = { type = "shared-lib"; };
    },
    {
        id = 501;
        action = "allow";
        operations = ["read"];
        object = { type = "ssl-cert"; };
    },

    # === DEFAULT ===
    {
        id = 999;
        action = "deny";
        operations = ["all"];
        # Log everything that falls through
    }
];
```

Labeling script:
```sh
#!/bin/sh
# Production stack labeling

# Entry points
setextattr system vlabel "type=entrypoint,app=nginx" /usr/local/sbin/nginx
setextattr system vlabel "type=entrypoint,app=php-fpm" /usr/local/sbin/php-fpm
setextattr system vlabel "type=entrypoint,app=postgres" /usr/local/bin/postgres

# Static content
find /usr/local/www/static -type f \
    -exec setextattr system vlabel "type=static-content" {} \;

# PHP application code
find /usr/local/www/app -name '*.php' \
    -exec setextattr system vlabel "type=php-code" {} \;

# Database files
find /var/db/postgres -type f \
    -exec setextattr system vlabel "type=postgres-data,layer=database" {} \;

# Logs
setextattr system vlabel "type=nginx-log" /var/log/nginx/*
setextattr system vlabel "type=postgres-log" /var/log/postgresql/*

# Session and upload directories
setextattr system vlabel "type=session-data" /var/lib/php/sessions
setextattr system vlabel "type=upload-tmp" /var/tmp/php-uploads

# Caches
setextattr system vlabel "type=nginx-cache" /var/cache/nginx

# SSL certificates
find /etc/ssl -name '*.pem' -o -name '*.crt' \
    -exec setextattr system vlabel "type=ssl-cert" {} \;

# Shared libraries
find /lib /usr/lib /usr/local/lib -name '*.so*' \
    -exec setextattr system vlabel "type=shared-lib" {} \;

# Config files
setextattr system vlabel "type=postgres-config" /usr/local/etc/postgresql/*
```

### Classified Research Environment

Multi-level security with need-to-know compartmentalization:

```ucl
# Classified Research Environment Policy

mode = "enforcing";
audit = "verbose";

rules = [
    # === TOP SECRET / SCI ACCESS ===
    {
        id = 10;
        action = "allow";
        operations = ["read"];
        subject = "clearance=topsecret,sci=true,indoc=current";
        object = "classification=topsecret,compartment=sci";
    },

    # === TOP SECRET GENERAL ===
    {
        id = 20;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { classification = "topsecret"; };
    },
    {
        id = 21;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "topsecret"; };
        object = { classification = "secret"; };
    },

    # === SECRET ACCESS ===
    {
        id = 30;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { classification = "secret"; };
    },
    {
        id = 31;
        action = "allow";
        operations = ["read"];
        subject = { clearance = "secret"; };
        object = { classification = "confidential"; };
    },

    # === PROJECT-BASED NEED-TO-KNOW ===
    # Project Alpha - only alpha-cleared personnel
    {
        id = 100;
        action = "allow";
        operations = ["read", "write"];
        subject = "project=alpha,need-to-know=true";
        object = "project=alpha";
    },
    # Project Beta
    {
        id = 101;
        action = "allow";
        operations = ["read", "write"];
        subject = "project=beta,need-to-know=true";
        object = "project=beta";
    },

    # Cross-project access denied
    {
        id = 150;
        action = "deny";
        operations = ["read", "write"];
        subject = { project = "alpha"; };
        object = { project = "beta"; };
    },
    {
        id = 151;
        action = "deny";
        operations = ["read", "write"];
        subject = { project = "beta"; };
        object = { project = "alpha"; };
    },

    # === FOREIGN NATIONAL RESTRICTIONS ===
    {
        id = 200;
        action = "deny";
        operations = ["read"];
        subject = { citizenship = "foreign"; };
        object = { handling = "noforn"; };
    },

    # === CONUS-ONLY DATA ===
    {
        id = 210;
        action = "deny";
        operations = ["read"];
        subject = "location=!conus";
        object = { handling = "conus-only"; };
    },

    # === WRITE CONTROLS (no write-down) ===
    {
        id = 300;
        action = "deny";
        operations = ["write"];
        subject = { clearance = "topsecret"; };
        object = { classification = "secret"; };
    },
    {
        id = 301;
        action = "deny";
        operations = ["write"];
        subject = { clearance = "topsecret"; };
        object = { classification = "confidential"; };
    },
    {
        id = 302;
        action = "deny";
        operations = ["write"];
        subject = { clearance = "secret"; };
        object = { classification = "confidential"; };
    },

    # === AUDIT REQUIREMENTS ===
    # All TS access must be logged (handled by audit=verbose)

    # === UNCLASSIFIED ACCESS ===
    {
        id = 900;
        action = "allow";
        operations = ["read", "write"];
        object = { classification = "unclassified"; };
    },

    {
        id = 999;
        action = "deny";
        operations = ["all"];
    }
];
```

---

## Debugging and Monitoring

### Enable Comprehensive Auditing

```sh
# Maximum verbosity
vlabelctl audit verbose

# Or via sysctl
sysctl security.mac.vlabel.audit_level=3
```

### Real-Time Monitoring

```sh
# Watch all decisions
vlabelctl monitor

# Example output:
# [14:30:01] ALLOW op=0x0001 pid=1234 uid=0
#            subj=layer=frontend,app=nginx
#            obj=type=static-content
#            path=/usr/local/www/index.html
# [14:30:02] DENY op=0x0004 pid=1235 uid=33
#            subj=layer=application,app=php-fpm
#            obj=type=postgres-data
#            path=/var/db/postgres/data
```

### Policy Testing

```sh
# Test access before deploying
vlabelctl test read \
    "layer=frontend,app=nginx" \
    "type=static-content"
# Result: ALLOW

vlabelctl test write \
    "layer=frontend,app=nginx" \
    "type=postgres-data"
# Result: DENY (rule 400)

# Test with complex labels
vlabelctl test read \
    "clearance=secret,project=alpha,need-to-know=true" \
    "classification=secret,project=alpha,handling=noforn"
# Result: ALLOW
```

### Validate Policy Before Loading

```sh
# Syntax check
vlabeld -t -v -c /etc/vlabel/policy.conf

# Output:
# loading policy from /etc/vlabel/policy.conf
# validated rule 100: action=2 ops=0x0001
# validated rule 101: action=0 ops=0x0002
# ...
# configuration OK
```

### Debug Label Issues

```sh
# Check if file is labeled
vlabelctl label get /path/to/file
# Output: type=data,domain=web (or "(no label)")

# Check statistics
vlabelctl stats
# vLabel Statistics:
#   Access checks:    1234567
#   Allowed:          1234500
#   Denied:           67
#   Labels read:      5000
#   Default labels:   200
#   Active rules:     45

# Find unlabeled files
find /data -exec sh -c '
    if ! getextattr -q system vlabel "$1" >/dev/null 2>&1; then
        echo "UNLABELED: $1"
    fi
' _ {} \;
```

---

## Advanced Pattern Examples

### Wildcard Key Matching

```sh
# Match any label with a "project" key (any value)
project=*

# Match any label with both "clearance" and "compartment" keys
clearance=*,compartment=*
```

### Complex Multi-Attribute Patterns

```ucl
rules = [
    # Match production database servers in US region
    {
        id = 1;
        action = "allow";
        operations = ["read", "write"];
        subject = "role=dba,region=us,env=production";
        object = "type=database,region=us,env=production";
    },

    # Match any frontend in any region
    {
        id = 2;
        action = "allow";
        operations = ["read"];
        subject = { tier = "frontend"; };
        object = { type = "config"; tier = "frontend"; };
    },

    # Complex: CI/CD pipeline with specific permissions
    {
        id = 10;
        action = "allow";
        operations = ["read", "write", "exec"];
        subject = "pipeline=deploy,stage=production,approved=true";
        object = "env=production,deployable=true";
    }
];
```

### Negation Patterns

```ucl
rules = [
    # Allow access to anything NOT marked as restricted
    {
        id = 1;
        action = "allow";
        operations = ["read"];
        object = { restricted = "true"; negate = true; };
        # This matches objects that do NOT have restricted=true
    },

    # Deny access to production from non-production subjects
    {
        id = 2;
        action = "deny";
        operations = ["write"];
        subject = { env = "production"; negate = true; };
        object = { env = "production"; };
    }
];
```

### Command-Line Pattern Syntax

```sh
# Using vlabelctl with complex patterns
vlabelctl rule add "allow read role=analyst,clearance=secret -> sensitivity=secret,compartment=*"

vlabelctl rule add "deny write !env=production -> env=production"

vlabelctl rule add "transition exec * -> type=entrypoint,app=nginx => layer=frontend,app=nginx"
```

---

## Quick Reference

### Label Format
```
key1=value1,key2=value2,...
```

### Pattern Format
```
key1=value1,key2=value2    # Match all pairs (AND)
key=*                       # Key exists (any value)
*                           # Match anything
!pattern                    # Negate match
```

### Operations
```
exec, read, write, mmap, link, rename, unlink,
chdir, stat, readdir, create, setextattr, getextattr,
lookup, open, access, all
```

### Actions
```
allow      # Permit the operation
deny       # Block the operation
transition # Allow and change process label
```

### Context Constraints
```
jail = "host"      # Must be on host
jail = "any"       # Must be in a jail
jail = 5           # Must be in jail ID 5
uid = 0            # Must be root
gid = 1000         # Must have GID 1000
sandboxed = true   # Must be in capability mode
tty = true         # Must have controlling terminal
```

### Size Limits
```
Label string:     12,288 bytes (12KB)
Key name:         63 bytes
Value:            255 bytes
Key-value pairs:  32 maximum
Rules:            1024 maximum
```
