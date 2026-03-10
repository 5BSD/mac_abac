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
│   │ SIGHUP Reload│           │ Label Mgmt   │                   │
│   │              │           │ Stats/Monitor│                   │
│   └──────┬───────┘           └──────┬───────┘                   │
│          │                          │                            │
│          └──────────┬───────────────┘                            │
│                     │ mac_syscall("vlabel", cmd, arg)            │
│                     ▼                                            │
│              MAC Framework Syscall Interface                     │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                        Kernel Space                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   mac_vlabel.ko                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                                                          │   │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │   │
│   │  │ Rules    │  │ Labels   │  │ DTrace   │              │   │
│   │  │ Engine   │  │ Cache    │  │ Probes   │              │   │
│   │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │   │
│   │       │             │             │                     │   │
│   │       └─────────────┼─────────────┘                     │   │
│   │                     │                                    │   │
│   │  ┌──────────────────┴──────────────────┐               │   │
│   │  │           vlabel_syscall()           │               │   │
│   │  │  (handles mac_syscall for "vlabel")  │               │   │
│   │  └──────────────────┬──────────────────┘               │   │
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
- Label parsing: `"key=val\nkey=val\n"` → struct
- Label matching against patterns
- Hash computation for fast comparison

```c
struct vlabel_label {
    char             vl_raw[VLABEL_MAX_LABEL_LEN];  // Original string (4KB)
    uint32_t         vl_hash;                        // Quick comparison
    uint32_t         vl_npairs;                      // Number of valid pairs
    struct vlabel_pair vl_pairs[VLABEL_MAX_PAIRS];  // Parsed key=value (16 max)
};

struct vlabel_pair {
    char vp_key[VLABEL_MAX_KEY_LEN];     // 64 bytes
    char vp_value[VLABEL_MAX_VALUE_LEN]; // 256 bytes
};
```

**Note:** Labels use arbitrary key=value pairs. The old type/domain/name/level
fields are removed in favor of flexible pairs.

### vlabel_rules.c - Rule Engine

- Rule storage array with rwlock protection
- First-match evaluation semantics
- Pattern matching with wildcards
- Context constraint checking (jail, capsicum, uid)
- Transition rule handling
- Rules appended at end (never reordered on removal)

```c
struct vlabel_rule {
    uint32_t                vr_id;           // Unique identifier
    uint8_t                 vr_action;       // ALLOW/DENY/TRANSITION
    uint32_t                vr_operations;   // Operation bitmask
    struct vlabel_rule_pattern vr_subject;   // Subject pattern (1,032 bytes)
    struct vlabel_rule_pattern vr_object;    // Object pattern (1,032 bytes)
    struct vlabel_context   vr_subj_context; // Subject constraints (24B)
    struct vlabel_context   vr_obj_context;  // Object constraints (24B)
    struct vlabel_label    *vr_newlabel;     // For transitions (pointer, NULL if not used)
};
// Size: ~2.1KB (non-transition), ~11KB (transition with allocated newlabel)
```

### vlabel_match.c - Pattern Matching

Separated from vlabel_label.c for clarity:
- `vlabel_pattern_match()` - Check label against pattern
- `vlabel_context_matches()` - Check process context constraints
- `vlabel_rule_matches()` - Full rule evaluation

### vlabel_syscall() - Syscall Interface

- Handles `mac_syscall("vlabel", cmd, arg)` from userland
- Provides all management operations (mode, audit, rules, stats)
- Variable-length data structures eliminate ioctl size limits
- Uses copyin/copyout for safe kernel-userland data transfer
- All commands require root privilege (PRIV_MAC_PARTITION)

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

### ZFS-Only Design

vLabel is designed exclusively for ZFS filesystems. The traditional FreeBSD MAC label
API (`mac_get_file`/`mac_set_file`, `getfmac`/`setfmac`) relies on filesystem callbacks:

- `mac_vnode_create_extattr()` - Called during file creation to set initial label
- `mac_vnode_setlabel_extattr()` - Called after `VOP_SETEXTATTR` to update cached label

ZFS does not implement these callbacks because it uses its own SA-based attribute system
rather than the UFS extattr infrastructure. The `MNT_MULTILABEL` mount flag that enables
these callbacks is not supported on ZFS.

**vLabel's approach works around this:**

1. Labels are read via `VOP_GETEXTATTR()` during `mac_vnode_associate_extattr()`
2. Labels are written via `VOP_SETEXTATTR()` through `vlabelctl`
3. Cached labels are refreshed via the `VLABEL_SYS_REFRESH` syscall
4. The `externalize_label`/`internalize_label` hooks are stubs (return errors)

This means `vlabelctl` is the only supported tool for label management. The standard
`getfmac`/`setfmac` tools will not work.

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

## Sysctl Tunables

vLabel exposes configuration and statistics via the `security.mac.vlabel` sysctl tree.

### Configuration Tunables (Read-Write)

| Sysctl | Type | Default | Description |
|--------|------|---------|-------------|
| `security.mac.vlabel.enabled` | int | 1 | Enable (1) or disable (0) the module |
| `security.mac.vlabel.mode` | int | 1 | 0=disabled, 1=permissive, 2=enforcing |
| `security.mac.vlabel.default_policy` | int | 0 | Default when no rule matches: 0=allow, 1=deny |
| `security.mac.vlabel.extattr_name` | string | "vlabel" | Extended attribute name in system namespace |

**Mode values:**
- `0` (disabled): All operations allowed, no rule evaluation
- `1` (permissive): Rules evaluated, denials logged but not enforced
- `2` (enforcing): Rules evaluated and enforced

### Statistics (Read-Only)

| Sysctl | Type | Description |
|--------|------|-------------|
| `security.mac.vlabel.checks` | uint64 | Total access checks performed |
| `security.mac.vlabel.allowed` | uint64 | Operations allowed |
| `security.mac.vlabel.denied` | uint64 | Operations denied (or would-deny in permissive) |
| `security.mac.vlabel.rule_count` | int | Currently loaded rules |
| `security.mac.vlabel.labels_read` | uint64 | Labels read from extended attributes |
| `security.mac.vlabel.labels_default` | uint64 | Default labels assigned (no extattr) |
| `security.mac.vlabel.labels_allocated` | uint64 | Label structures allocated |
| `security.mac.vlabel.labels_freed` | uint64 | Label structures freed |
| `security.mac.vlabel.parse_errors` | uint64 | Label parse failures |

### Example Usage

```sh
# View all tunables
sysctl security.mac.vlabel

# Set enforcing mode
sysctl security.mac.vlabel.mode=2

# Set default deny policy
sysctl security.mac.vlabel.default_policy=1

# Check statistics
sysctl security.mac.vlabel.checks security.mac.vlabel.denied
```

## mac_syscall Interface

vLabel uses the FreeBSD MAC Framework's syscall interface (`mac_syscall()`) instead of
a character device. This provides several benefits:

- **No filesystem dependency**: Works before filesystems are mounted
- **No ioctl size limits**: Variable-length data eliminates the 8KB IOCPARM_MAX restriction
- **Simpler architecture**: No device node management

### Syscall Commands

All commands use: `mac_syscall("vlabel", VLABEL_SYS_*, arg)`

| Command | Direction | Argument | Purpose |
|---------|-----------|----------|---------|
| `VLABEL_SYS_GETMODE` | Read | `int*` | Get current mode |
| `VLABEL_SYS_SETMODE` | Write | `int*` | Set mode (0/1/2) |
| `VLABEL_SYS_GETSTATS` | Read | `struct vlabel_stats*` | Get statistics |
| `VLABEL_SYS_GETDEFPOL` | Read | `int*` | Get default policy |
| `VLABEL_SYS_SETDEFPOL` | Write | `int*` | Set default policy |
| `VLABEL_SYS_RULE_ADD` | Write | `struct vlabel_rule_arg*` | Add a rule |
| `VLABEL_SYS_RULE_REMOVE` | Write | `uint32_t*` | Remove rule by ID |
| `VLABEL_SYS_RULE_CLEAR` | None | `NULL` | Clear all rules |
| `VLABEL_SYS_RULE_LIST` | Read | `struct vlabel_rule_list_arg*` | List rules |
| `VLABEL_SYS_TEST` | Read/Write | `struct vlabel_test_arg*` | Test access |
| `VLABEL_SYS_REFRESH` | Write | `int*` (fd) | Refresh cached label from extattr |
| `VLABEL_SYS_SETLABEL` | Write | `struct vlabel_setlabel_arg*` | Atomic set: extattr + cache |

### Variable-Length Structures

The syscall API uses variable-length structures to support large labels:

```c
struct vlabel_rule_arg {
    uint8_t   vr_action;       // ALLOW/DENY/TRANSITION
    uint8_t   vr_reserved[3];
    uint32_t  vr_operations;   // Operation bitmask
    uint32_t  vr_subject_flags;
    uint32_t  vr_object_flags;
    struct vlabel_context_arg vr_context;
    uint16_t  vr_subject_len;  // Length including null
    uint16_t  vr_object_len;
    uint16_t  vr_newlabel_len; // 0 if not transition
    uint16_t  vr_reserved2;
    // Variable data follows: subject, object, newlabel
};
```

### Example Usage (C)

```c
#include <sys/mac.h>
#include "mac_vlabel.h"

// Get current mode
int mode;
if (mac_syscall("vlabel", VLABEL_SYS_GETMODE, &mode) == 0)
    printf("Mode: %d\n", mode);

// Set enforcing mode
int newmode = VLABEL_MODE_ENFORCING;
mac_syscall("vlabel", VLABEL_SYS_SETMODE, &newmode);

// Add a rule
size_t subject_len = strlen("*") + 1;
size_t object_len = strlen("type=untrusted") + 1;
size_t total = sizeof(struct vlabel_rule_arg) + subject_len + object_len;

char *buf = malloc(total);
struct vlabel_rule_arg *arg = (struct vlabel_rule_arg *)buf;
arg->vr_action = VLABEL_ACTION_DENY;
arg->vr_operations = VLABEL_OP_EXEC;
arg->vr_subject_len = subject_len;
arg->vr_object_len = object_len;
arg->vr_newlabel_len = 0;
// ... copy strings after header
mac_syscall("vlabel", VLABEL_SYS_RULE_ADD, arg);
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
- Adding/removing rules: root (via mac_syscall)
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

## DTrace Integration

vLabel provides DTrace probes for detailed instrumentation and debugging. These probes fire
on key events in the policy module, allowing real-time observation without recompilation.

### Available Probes

| Probe | Arguments | Description |
|-------|-----------|-------------|
| `vlabel:::check-entry` | subj, obj, op | Start of access check |
| `vlabel:::check-return` | result, op | End of access check |
| `vlabel:::check-allow` | subj, obj, op, rule_id | Access allowed |
| `vlabel:::check-deny` | subj, obj, op, rule_id | Access denied |
| `vlabel:::rule-match` | rule_id, action, op | Rule matched |
| `vlabel:::rule-nomatch` | default_policy, op | No rule matched |
| `vlabel:::transition-exec` | old_label, new_label, exec_label, pid | Label transition on exec |
| `vlabel:::extattr-read` | label, vnode | Label read from extattr |
| `vlabel:::extattr-default` | is_subject | Default label assigned |
| `vlabel:::rule-add` | rule_id, action, ops | Rule added |
| `vlabel:::rule-remove` | rule_id | Rule removed |
| `vlabel:::rule-clear` | count | All rules cleared |
| `vlabel:::mode-change` | old_mode, new_mode | Enforcement mode changed |

### Example DTrace Commands

```sh
# Watch all denied accesses
dtrace -n 'vlabel:::check-deny { printf("%s -> %s op=0x%x rule=%u",
    stringof(arg0), stringof(arg1), arg2, arg3); }'

# Count denials by operation
dtrace -n 'vlabel:::check-deny { @[arg2] = count(); }'

# Measure access check latency
dtrace -n 'vlabel:::check-entry { self->ts = timestamp; }
           vlabel:::check-return /self->ts/ {
               @["ns"] = quantize(timestamp - self->ts);
               self->ts = 0;
           }'

# Watch label transitions
dtrace -n 'vlabel:::transition-exec {
    printf("pid %d: %s -> %s (via %s)",
        arg3, stringof(arg0), stringof(arg1), stringof(arg2)); }'

# Count rule matches by rule ID
dtrace -n 'vlabel:::rule-match { @[arg0] = count(); }'

# Watch mode changes
dtrace -n 'vlabel:::mode-change {
    printf("mode: %d -> %d", arg0, arg1); }'
```

### Probe Categories

**Access Check Probes**: `check-entry`, `check-return`, `check-allow`, `check-deny`
- Fired during every access check
- Use for latency measurement, denial debugging, policy validation

**Rule Probes**: `rule-match`, `rule-nomatch`, `rule-add`, `rule-remove`, `rule-clear`
- Fired during rule evaluation and management
- Use for rule debugging, policy testing, coverage analysis

**Transition Probes**: `transition-exec`
- Fired when a process label changes during exec
- Use for tracking privilege escalation, sandboxing

**Label Probes**: `extattr-read`, `extattr-default`
- Fired when labels are read from filesystem or defaults assigned
- Use for understanding label propagation

## Memory Analysis

### Structure Sizes

| Structure | Size | Notes |
|-----------|------|-------|
| `vlabel_pair` | 320 bytes | 64 key + 256 value (file labels) |
| `vlabel_label` | ~9,224 bytes | 4096 raw + 8 meta + 16×320 pairs |
| `vlabel_rule_pair` | 128 bytes | 64 key + 64 value (rule patterns) |
| `vlabel_rule_pattern` | 1,032 bytes | 8 meta + 8×128 pairs |
| `vlabel_context` | 24 bytes | Flags + uid/gid/jail |
| `vlabel_rule` (non-transition) | **~2,132 bytes** | Subject + object patterns + contexts |
| `vlabel_rule` (transition) | **~11,356 bytes** | +9KB for allocated newlabel |

### Memory Usage at Scale

| Rules | Non-Transition | With 10% Transitions |
|-------|----------------|----------------------|
| 100 | 213 KB | 1.1 MB |
| 1,024 | 2.1 MB | 11 MB |
| 4,096 | 8.5 MB | 45 MB |

### Design Rationale

File labels and rule patterns have different requirements:

**File labels** (`vlabel_label`, `vlabel_pair`):
- Stored in extended attributes, cached per-vnode
- May contain paths, descriptions, complex values
- 16 pairs × (64-byte key + 256-byte value) = 5KB per label
- Size is acceptable because labels are sparse (most files unlabeled)

**Rule patterns** (`vlabel_rule_pattern`, `vlabel_rule_pair`):
- Loaded into kernel memory for every rule
- Contain short identifiers: type names, domains, categories
- Analysis shows 1-4 pairs typical, values rarely exceed 30 chars
- 8 pairs × (64-byte key + 64-byte value) = 1KB per pattern

**Transition labels** (`vr_newlabel` pointer):
- Only ~5-10% of rules are transition rules
- Allocated separately only when needed
- Non-transition rules save ~9KB each

## System Limits

| Limit | Value | Scope | Notes |
|-------|-------|-------|-------|
| Max rules | 4,096 | System-wide | ~8.5 MB for non-transition rules |
| Max pairs per file label | 16 | Per label | Complex labels need this |
| Max pairs per rule pattern | 8 | Per pattern | Analysis shows 1-4 typical |
| Max key length (labels) | 64 bytes | Per key | Same for labels and rules |
| Max value length (labels) | 256 bytes | Per value | Paths, descriptions |
| Max value length (rules) | 64 bytes | Per value | Short identifiers only |
| Max label length | 4,096 bytes | Per extattr | Soft limit for storage |
