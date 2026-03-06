# vLabel Architecture

vLabel is a FreeBSD Mandatory Access Control Framework (MACF) policy module. This document describes the system architecture, kernel hooks, and component interactions.

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   vlabeld                    vlabelctl                          │
│   ┌──────────────┐           ┌──────────────┐                   │
│   │ Policy Parser│           │ CLI Commands │                   │
│   │ Audit Logger │           │ Label Mgmt   │                   │
│   │ SIGHUP Reload│           │ Stats/Monitor│                   │
│   └──────┬───────┘           └──────┬───────┘                   │
│          │                          │                            │
│          └──────────┬───────────────┘                            │
│                     │ ioctl / read                               │
│                     ▼                                            │
│              /dev/vlabel                                         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                        Kernel Space                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   mac_vlabel.ko                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                                                          │   │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │   │
│   │  │ Rules    │  │ Labels   │  │ Audit    │              │   │
│   │  │ Engine   │  │ Cache    │  │ Buffer   │              │   │
│   │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │   │
│   │       │             │             │                     │   │
│   │       └─────────────┼─────────────┘                     │   │
│   │                     │                                    │   │
│   │              ┌──────┴──────┐                            │   │
│   │              │ MACF Hooks  │                            │   │
│   │              │ (48 hooks)  │                            │   │
│   │              └──────┬──────┘                            │   │
│   │                     │                                    │   │
│   └─────────────────────┼────────────────────────────────────┘   │
│                         │                                        │
│                         ▼                                        │
│                  FreeBSD MACF                                    │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                       Filesystem                                 │
│                                                                  │
│   Extended Attributes: system:vlabel                            │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ /bin/ls        → (no label - default)                    │   │
│   │ /usr/bin/app   → type=trusted,domain=system              │   │
│   │ /home/dl/x.sh  → type=untrusted                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Kernel Module Components

### mac_vlabel.c - Module Core

- MACF policy registration via `MAC_POLICY_SET()`
- Sysctl tree setup (`security.mac.vlabel.*`)
- Global state: enabled flag, mode, audit level
- Coordination between submodules

### vlabel_label.c - Label Management

- UMA zone for label allocation (`vlabel_label_zone`)
- Label parsing: `"key=val,key=val"` → struct
- Label matching against patterns
- Hash computation for fast comparison

```c
struct vlabel_label {
    char    *vl_raw;      // Original string
    uint32_t vl_hash;     // Quick comparison
    char    *vl_type;     // Parsed type= value
    char    *vl_domain;   // Parsed domain= value
    char    *vl_name;     // Parsed name= value
    char    *vl_level;    // Parsed level= value
};
```

### vlabel_rules.c - Rule Engine

- Rule storage array with rwlock protection
- First-match evaluation semantics
- Pattern matching with wildcards
- Context constraint checking (jail, capsicum, uid)
- Transition rule handling

```c
struct vlabel_rule {
    uint32_t         vr_id;
    uint8_t          vr_action;     // ALLOW/DENY/TRANSITION
    uint32_t         vr_operations; // Bitmask
    struct vlabel_pattern vr_subject;
    struct vlabel_pattern vr_object;
    struct vlabel_context vr_context;
    char             vr_newlabel[256];
};
```

### vlabel_dev.c - Device Interface

- Character device `/dev/vlabel`
- ioctl handlers for mode/audit/rules/stats
- Read interface for audit events
- Poll support for non-blocking audit reads

### vlabel_audit.c - Audit System

- Ring buffer for audit entries
- Selectable notification for readers
- Overflow handling with drop counter
- Entry format with timestamp, labels, path

```c
struct vlabel_audit_entry {
    uint64_t vae_timestamp;
    uint32_t vae_type;
    uint32_t vae_operation;
    int32_t  vae_result;
    int32_t  vae_pid;
    uint32_t vae_uid;
    int32_t  vae_jailid;
    char     vae_subject_label[64];
    char     vae_object_label[64];
    char     vae_path[256];
};
```

### vlabel_vnode.c - Vnode Hooks

Implements all vnode (file) access checks:
- `check_exec`, `check_read`, `check_write`
- `check_open`, `check_mmap`, `check_stat`
- `check_unlink`, `check_rename`, `check_link`
- `check_create`, `check_chdir`, `check_lookup`
- Extended attribute hooks for label protection

### vlabel_cred.c - Credential Hooks

Manages process (subject) labels:
- `cred_init_label` - Initialize on process creation
- `cred_copy_label` - Copy on fork
- `execve_transition` - Label change on exec
- `execve_will_transition` - Check if transition occurs

### vlabel_proc.c - Process Hooks

Inter-process access control:
- `proc_check_debug` - ptrace/procfs access
- `proc_check_signal` - Signal delivery
- `proc_check_sched` - Scheduler operations

## MACF Integration

### Hook Registration

```c
static struct mac_policy_ops vlabel_ops = {
    // Lifecycle
    .mpo_init = vlabel_init,
    .mpo_destroy = vlabel_destroy,

    // Vnode checks (31 hooks)
    .mpo_vnode_check_exec = vlabel_vnode_check_exec,
    .mpo_vnode_check_read = vlabel_vnode_check_read,
    // ... etc

    // Credential lifecycle (10 hooks)
    .mpo_cred_init_label = vlabel_cred_init_label,
    // ... etc
};

MAC_POLICY_SET(&vlabel_ops, mac_vlabel, "vLabel MAC Policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &vlabel_slot);
```

### Label Slot

MACF provides a "slot" for each policy to store per-object data:

```c
static int vlabel_slot;  // Assigned by MACF

// Access label on any labeled object
#define SLOT(l) mac_label_get((l), vlabel_slot)
```

### Hook Flow

```
User calls open("/path/to/file", O_RDONLY)
    │
    ▼
VFS: vn_open()
    │
    ▼
MACF: mac_vnode_check_open()
    │
    ├── Calls each registered policy's mpo_vnode_check_open
    │
    ▼
vLabel: vlabel_vnode_check_open()
    │
    ├── Get subject label from cred->cr_label
    ├── Get object label from vp->v_label (cached from extattr)
    ├── Evaluate rules for VLABEL_OP_OPEN
    ├── Log audit event if configured
    │
    ▼
Return 0 (allow) or EACCES (deny)
```

## Extended Attribute Flow

### Reading Labels

```
File accessed (open, exec, stat, etc.)
    │
    ▼
MACF: mac_vnode_associate_extattr()
    │
    ▼
vLabel: vlabel_vnode_associate_extattr()
    │
    ├── VOP_GETEXTATTR(vp, SYSTEM, "vlabel", ...)
    │   │
    │   ▼
    │   Filesystem returns extattr value or ENOATTR
    │
    ├── If found: Parse label string, store in slot
    ├── If ENOATTR: Use default label
    │
    ▼
Label cached in vnode for future checks
```

### Writing Labels

```
setextattr system vlabel "type=foo" /path
    │
    ▼
VFS: VOP_SETEXTATTR()
    │
    ▼
MACF: mac_vnode_check_setextattr()
    │
    ▼
vLabel: vlabel_vnode_check_setextattr()
    │
    ├── Check if caller can modify labels
    ├── (Currently: require root)
    │
    ▼
Filesystem stores extattr
    │
    ▼
MACF: mac_vnode_setlabel_extattr()
    │
    ▼
vLabel: vlabel_vnode_setlabel_extattr()
    │
    ├── Parse new label
    ├── Update cached label in slot
    │
    ▼
Done
```

## Device Interface

### ioctls

| ioctl | Direction | Purpose |
|-------|-----------|---------|
| `VLABEL_IOC_GETMODE` | Read | Get current mode |
| `VLABEL_IOC_SETMODE` | Write | Set mode (0/1/2) |
| `VLABEL_IOC_GETSTATS` | Read | Get statistics struct |
| `VLABEL_IOC_SETAUDIT` | Write | Set audit level |
| `VLABEL_IOC_RULE_ADD` | Write | Add a rule |
| `VLABEL_IOC_RULE_REMOVE` | Write | Remove rule by ID |
| `VLABEL_IOC_RULES_CLEAR` | None | Clear all rules |

### Audit Read

```c
// Blocking read for audit events
struct vlabel_audit_entry entry;
read(fd, &entry, sizeof(entry));

// Non-blocking with poll
struct pollfd pfd = { .fd = fd, .events = POLLIN };
poll(&pfd, 1, timeout);
if (pfd.revents & POLLIN)
    read(fd, &entry, sizeof(entry));
```

## Statistics

Available via sysctl or ioctl:

| Statistic | Description |
|-----------|-------------|
| `checks` | Total access checks performed |
| `allowed` | Operations allowed |
| `denied` | Operations denied |
| `labels_read` | Labels read from extattr |
| `labels_default` | Default labels assigned |
| `labels_allocated` | Label structs allocated |
| `labels_freed` | Label structs freed |
| `rule_count` | Currently loaded rules |
| `parse_errors` | Label parse failures |
| `audit_events` | Pending audit entries |
| `audit_dropped` | Dropped due to full buffer |

## Memory Management

### UMA Zones

```c
vlabel_label_zone = uma_zcreate("vlabel_label",
    sizeof(struct vlabel_label),
    NULL, NULL, NULL, NULL,
    UMA_ALIGN_PTR, 0);
```

Labels are allocated from a UMA zone for:
- Fast allocation/deallocation
- Memory accounting
- Cache efficiency

### Locking

| Lock | Type | Protects |
|------|------|----------|
| `vlabel_rules_lock` | rwlock | Rules array |
| `vlabel_audit_mtx` | mutex | Audit ring buffer |

Rule evaluation takes a read lock (allows concurrent checks).
Rule modification takes a write lock (exclusive).

## Security Considerations

### Privilege Requirements

- Loading module: root
- Setting labels (system namespace): root
- Adding/removing rules: root (via /dev/vlabel)
- Reading audit events: root

### Self-Protection

The module protects its own extended attribute:
- `check_setextattr` can deny modifications to `system:vlabel`
- Currently allows root; could be restricted further

### Fail-Safe Behavior

- Disabled mode: All operations allowed
- Module unload: All operations allowed
- Parse errors: Logged, operation continues
- Missing labels: Default label used (matches wildcards)
