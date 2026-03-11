# ABAC Architecture

ABAC is a FreeBSD Mandatory Access Control Framework (MACF) policy module. This document describes the system architecture, kernel hooks, and component interactions.

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   mac_abacd                    mac_abac_ctl                          │
│   ┌──────────────┐           ┌──────────────┐                   │
│   │ Policy Parser│           │ CLI Commands │                   │
│   │ SIGHUP Reload│           │ Label Mgmt   │                   │
│   │              │           │ Stats/Monitor│                   │
│   └──────┬───────┘           └──────┬───────┘                   │
│          │                          │                            │
│          └──────────┬───────────────┘                            │
│                     │ mac_syscall("mac_abac", cmd, arg)            │
│                     ▼                                            │
│              MAC Framework Syscall Interface                     │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                        Kernel Space                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   mac_abac.ko                                                  │
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
│   │  │           abac_syscall()           │               │   │
│   │  │  (handles mac_syscall for "mac_abac")  │               │   │
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
│   Extended Attributes: system:mac_abac                            │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ /bin/ls        → (no label - default)                    │   │
│   │ /usr/bin/app   → type=trusted,domain=system              │   │
│   │ /home/dl/x.sh  → type=untrusted                          │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Kernel Module Components

### mac_abac.c - Module Core

- MACF policy registration via `MAC_POLICY_SET()`
- Sysctl tree setup (`security.mac.mac_abac.*`)
- Global state: enabled flag, mode, audit level
- Coordination between submodules

### abac_label.c - Label Management

- UMA zone for label allocation (`abac_label_zone`)
- Label parsing: `"key=val\nkey=val\n"` → struct
- Label matching against patterns
- Hash computation for fast comparison

```c
struct abac_label {
    char             vl_raw[ABAC_MAX_LABEL_LEN];  // Original string (4KB)
    uint32_t         vl_hash;                        // Quick comparison
    uint32_t         vl_npairs;                      // Number of valid pairs
    struct abac_pair vl_pairs[ABAC_MAX_PAIRS];  // Parsed key=value (16 max)
};

struct abac_pair {
    char vp_key[ABAC_MAX_KEY_LEN];     // 64 bytes
    char vp_value[ABAC_MAX_VALUE_LEN]; // 256 bytes
};
```

**Note:** Labels use arbitrary key=value pairs. The old type/domain/name/level
fields are removed in favor of flexible pairs.

### abac_rules.c - Rule Engine

- Rule storage array with rwlock protection
- First-match evaluation semantics
- Pattern matching with wildcards
- Context constraint checking (jail, capsicum, uid)
- Transition rule handling
- Rules appended at end (never reordered on removal)

```c
struct abac_rule {
    uint32_t                vr_id;           // Unique identifier
    uint8_t                 vr_action;       // ALLOW/DENY/TRANSITION
    uint32_t                vr_operations;   // Operation bitmask
    struct abac_rule_pattern vr_subject;   // Subject pattern (1,032 bytes)
    struct abac_rule_pattern vr_object;    // Object pattern (1,032 bytes)
    struct abac_context   vr_subj_context; // Subject constraints (24B)
    struct abac_context   vr_obj_context;  // Object constraints (24B)
    struct abac_label    *vr_newlabel;     // For transitions (pointer, NULL if not used)
};
// Size: ~2.1KB (non-transition), ~11KB (transition with allocated newlabel)
```

### abac_match.c - Pattern Matching

Separated from abac_label.c for clarity:
- `abac_pattern_match()` - Check label against pattern
- `abac_context_matches()` - Check process context constraints
- `abac_rule_matches()` - Full rule evaluation

### abac_syscall() - Syscall Interface

- Handles `mac_syscall("mac_abac", cmd, arg)` from userland
- Provides all management operations (mode, audit, rules, stats)
- Variable-length data structures eliminate ioctl size limits
- Uses copyin/copyout for safe kernel-userland data transfer
- All commands require root privilege (PRIV_MAC_PARTITION)

### abac_vnode.c - Vnode Hooks

Implements all vnode (file) access checks:
- `check_exec`, `check_read`, `check_write`
- `check_open`, `check_mmap`, `check_stat`
- `check_unlink`, `check_rename`, `check_link`
- `check_create`, `check_chdir`, `check_lookup`
- Extended attribute hooks for label protection

### abac_cred.c - Credential Hooks

Manages process (subject) labels:
- `cred_init_label` - Initialize on process creation
- `cred_copy_label` - Copy on fork
- `execve_transition` - Label change on exec
- `execve_will_transition` - Check if transition occurs

### abac_proc.c - Process Hooks

Inter-process access control:
- `proc_check_debug` - ptrace/procfs access
- `proc_check_signal` - Signal delivery
- `proc_check_sched` - Scheduler operations

## MACF Integration

### Hook Registration

```c
static struct mac_policy_ops abac_ops = {
    // Lifecycle
    .mpo_init = abac_init,
    .mpo_destroy = abac_destroy,

    // Vnode checks (31 hooks)
    .mpo_vnode_check_exec = abac_vnode_check_exec,
    .mpo_vnode_check_read = abac_vnode_check_read,
    // ... etc

    // Credential lifecycle (10 hooks)
    .mpo_cred_init_label = abac_cred_init_label,
    // ... etc
};

MAC_POLICY_SET(&abac_ops, mac_abac, "ABAC MAC Policy",
    MPC_LOADTIME_FLAG_UNLOADOK, &abac_slot);
```

### Label Slot

MACF provides a "slot" for each policy to store per-object data:

```c
static int abac_slot;  // Assigned by MACF

// Access label on any labeled object
#define SLOT(l) mac_label_get((l), abac_slot)
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
ABAC: abac_vnode_check_open()
    │
    ├── Get subject label from cred->cr_label
    ├── Get object label from vp->v_label (cached from extattr)
    ├── Evaluate rules for ABAC_OP_OPEN
    ├── Log audit event if configured
    │
    ▼
Return 0 (allow) or EACCES (deny)
```

## Extended Attribute Flow

### ZFS-Only Design

ABAC is designed exclusively for ZFS filesystems. The traditional FreeBSD MAC label
API (`mac_get_file`/`mac_set_file`, `getfmac`/`setfmac`) relies on filesystem callbacks:

- `mac_vnode_create_extattr()` - Called during file creation to set initial label
- `mac_vnode_setlabel_extattr()` - Called after `VOP_SETEXTATTR` to update cached label

ZFS does not implement these callbacks because it uses its own SA-based attribute system
rather than the UFS extattr infrastructure. The `MNT_MULTILABEL` mount flag that enables
these callbacks is not supported on ZFS.

**ABAC's approach works around this:**

1. Labels are read via `VOP_GETEXTATTR()` during `mac_vnode_associate_extattr()`
2. Labels are written via `VOP_SETEXTATTR()` through `mac_abac_ctl`
3. Cached labels are refreshed via the `ABAC_SYS_REFRESH` syscall
4. The `externalize_label`/`internalize_label` hooks are stubs (return errors)

This means `mac_abac_ctl` is the only supported tool for label management. The standard
`getfmac`/`setfmac` tools will not work.

### Reading Labels

```
File accessed (open, exec, stat, etc.)
    │
    ▼
MACF: mac_vnode_associate_extattr()
    │
    ▼
ABAC: abac_vnode_associate_extattr()
    │
    ├── VOP_GETEXTATTR(vp, SYSTEM, "mac_abac", ...)
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
setextattr system mac_abac "type=foo" /path
    │
    ▼
VFS: VOP_SETEXTATTR()
    │
    ▼
MACF: mac_vnode_check_setextattr()
    │
    ▼
ABAC: abac_vnode_check_setextattr()
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
ABAC: abac_vnode_setlabel_extattr()
    │
    ├── Parse new label
    ├── Update cached label in slot
    │
    ▼
Done
```

## Sysctl Tunables

ABAC exposes configuration and statistics via the `security.mac.mac_abac` sysctl tree.

### Configuration Tunables (Read-Write)

| Sysctl | Type | Default | Description |
|--------|------|---------|-------------|
| `security.mac.mac_abac.enabled` | int | 1 | Enable (1) or disable (0) the module |
| `security.mac.mac_abac.mode` | int | 1 | 0=disabled, 1=permissive, 2=enforcing |
| `security.mac.mac_abac.default_policy` | int | 0 | Default when no rule matches: 0=allow, 1=deny |
| `security.mac.mac_abac.extattr_name` | string | "mac_abac" | Extended attribute name in system namespace |

**Mode values:**
- `0` (disabled): All operations allowed, no rule evaluation
- `1` (permissive): Rules evaluated, denials logged but not enforced
- `2` (enforcing): Rules evaluated and enforced

### Statistics (Read-Only)

| Sysctl | Type | Description |
|--------|------|-------------|
| `security.mac.mac_abac.checks` | uint64 | Total access checks performed |
| `security.mac.mac_abac.allowed` | uint64 | Operations allowed |
| `security.mac.mac_abac.denied` | uint64 | Operations denied (or would-deny in permissive) |
| `security.mac.mac_abac.rule_count` | int | Currently loaded rules |
| `security.mac.mac_abac.labels_read` | uint64 | Labels read from extended attributes |
| `security.mac.mac_abac.labels_default` | uint64 | Default labels assigned (no extattr) |
| `security.mac.mac_abac.labels_allocated` | uint64 | Label structures allocated |
| `security.mac.mac_abac.labels_freed` | uint64 | Label structures freed |
| `security.mac.mac_abac.parse_errors` | uint64 | Label parse failures |

### Example Usage

```sh
# View all tunables
sysctl security.mac.mac_abac

# Set enforcing mode
sysctl security.mac.mac_abac.mode=2

# Set default deny policy
sysctl security.mac.mac_abac.default_policy=1

# Check statistics
sysctl security.mac.mac_abac.checks security.mac.mac_abac.denied
```

## mac_syscall Interface

ABAC uses the FreeBSD MAC Framework's syscall interface (`mac_syscall()`) instead of
a character device. This provides several benefits:

- **No filesystem dependency**: Works before filesystems are mounted
- **No ioctl size limits**: Variable-length data eliminates the 8KB IOCPARM_MAX restriction
- **Simpler architecture**: No device node management

### Syscall Commands

All commands use: `mac_syscall("mac_abac", ABAC_SYS_*, arg)`

| Command | Direction | Argument | Purpose |
|---------|-----------|----------|---------|
| `ABAC_SYS_GETMODE` | Read | `int*` | Get current mode |
| `ABAC_SYS_SETMODE` | Write | `int*` | Set mode (0/1/2) |
| `ABAC_SYS_GETSTATS` | Read | `struct abac_stats*` | Get statistics |
| `ABAC_SYS_GETDEFPOL` | Read | `int*` | Get default policy |
| `ABAC_SYS_SETDEFPOL` | Write | `int*` | Set default policy |
| `ABAC_SYS_RULE_ADD` | Write | `struct abac_rule_arg*` | Add a rule |
| `ABAC_SYS_RULE_REMOVE` | Write | `uint32_t*` | Remove rule by ID |
| `ABAC_SYS_RULE_CLEAR` | None | `NULL` | Clear all rules |
| `ABAC_SYS_RULE_LIST` | Read | `struct abac_rule_list_arg*` | List rules |
| `ABAC_SYS_TEST` | Read/Write | `struct abac_test_arg*` | Test access |
| `ABAC_SYS_REFRESH` | Write | `int*` (fd) | Refresh cached label from extattr |
| `ABAC_SYS_SETLABEL` | Write | `struct abac_setlabel_arg*` | Atomic set: extattr + cache |

### Variable-Length Structures

The syscall API uses variable-length structures to support large labels:

```c
struct abac_rule_arg {
    uint8_t   vr_action;       // ALLOW/DENY/TRANSITION
    uint8_t   vr_reserved[3];
    uint32_t  vr_operations;   // Operation bitmask
    uint32_t  vr_subject_flags;
    uint32_t  vr_object_flags;
    struct abac_context_arg vr_context;
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
#include "mac_abac.h"

// Get current mode
int mode;
if (mac_syscall("mac_abac", ABAC_SYS_GETMODE, &mode) == 0)
    printf("Mode: %d\n", mode);

// Set enforcing mode
int newmode = ABAC_MODE_ENFORCING;
mac_syscall("mac_abac", ABAC_SYS_SETMODE, &newmode);

// Add a rule
size_t subject_len = strlen("*") + 1;
size_t object_len = strlen("type=untrusted") + 1;
size_t total = sizeof(struct abac_rule_arg) + subject_len + object_len;

char *buf = malloc(total);
struct abac_rule_arg *arg = (struct abac_rule_arg *)buf;
arg->vr_action = ABAC_ACTION_DENY;
arg->vr_operations = ABAC_OP_EXEC;
arg->vr_subject_len = subject_len;
arg->vr_object_len = object_len;
arg->vr_newlabel_len = 0;
// ... copy strings after header
mac_syscall("mac_abac", ABAC_SYS_RULE_ADD, arg);
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
abac_label_zone = uma_zcreate("abac_label",
    sizeof(struct abac_label),
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
| `abac_rules_lock` | rwlock | Rules array |
| `abac_audit_mtx` | mutex | Audit ring buffer |

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
- `check_setextattr` can deny modifications to `system:mac_abac`
- Currently allows root; could be restricted further

### Fail-Safe Behavior

- Disabled mode: All operations allowed
- Module unload: All operations allowed
- Parse errors: Logged, operation continues
- Missing labels: Default label used (matches wildcards)

## DTrace Integration

ABAC provides DTrace probes for detailed instrumentation and debugging. These probes fire
on key events in the policy module, allowing real-time observation without recompilation.

### Available Probes

| Probe | Arguments | Description |
|-------|-----------|-------------|
| `mac_abac:::check-entry` | subj, obj, op | Start of access check |
| `mac_abac:::check-return` | result, op | End of access check |
| `mac_abac:::check-allow` | subj, obj, op, rule_id | Access allowed |
| `mac_abac:::check-deny` | subj, obj, op, rule_id | Access denied |
| `mac_abac:::rule-match` | rule_id, action, op | Rule matched |
| `mac_abac:::rule-nomatch` | default_policy, op | No rule matched |
| `mac_abac:::transition-exec` | old_label, new_label, exec_label, pid | Label transition on exec |
| `mac_abac:::extattr-read` | label, vnode | Label read from extattr |
| `mac_abac:::extattr-default` | is_subject | Default label assigned |
| `mac_abac:::rule-add` | rule_id, action, ops | Rule added |
| `mac_abac:::rule-remove` | rule_id | Rule removed |
| `mac_abac:::rule-clear` | count | All rules cleared |
| `mac_abac:::mode-change` | old_mode, new_mode | Enforcement mode changed |

### Example DTrace Commands

```sh
# Watch all denied accesses
dtrace -n 'mac_abac:::check-deny { printf("%s -> %s op=0x%x rule=%u",
    stringof(arg0), stringof(arg1), arg2, arg3); }'

# Count denials by operation
dtrace -n 'mac_abac:::check-deny { @[arg2] = count(); }'

# Measure access check latency
dtrace -n 'mac_abac:::check-entry { self->ts = timestamp; }
           mac_abac:::check-return /self->ts/ {
               @["ns"] = quantize(timestamp - self->ts);
               self->ts = 0;
           }'

# Watch label transitions
dtrace -n 'mac_abac:::transition-exec {
    printf("pid %d: %s -> %s (via %s)",
        arg3, stringof(arg0), stringof(arg1), stringof(arg2)); }'

# Count rule matches by rule ID
dtrace -n 'mac_abac:::rule-match { @[arg0] = count(); }'

# Watch mode changes
dtrace -n 'mac_abac:::mode-change {
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
| `abac_pair` | 320 bytes | 64 key + 256 value (file labels) |
| `abac_label` | ~9,224 bytes | 4096 raw + 8 meta + 16×320 pairs |
| `abac_rule_pair` | 128 bytes | 64 key + 64 value (rule patterns) |
| `abac_rule_pattern` | 1,032 bytes | 8 meta + 8×128 pairs |
| `abac_context` | 24 bytes | Flags + uid/gid/jail |
| `abac_rule` (non-transition) | **~2,132 bytes** | Subject + object patterns + contexts |
| `abac_rule` (transition) | **~11,356 bytes** | +9KB for allocated newlabel |

### Memory Usage at Scale

| Rules | Non-Transition | With 10% Transitions |
|-------|----------------|----------------------|
| 100 | 213 KB | 1.1 MB |
| 1,024 | 2.1 MB | 11 MB |
| 4,096 | 8.5 MB | 45 MB |

### Design Rationale

File labels and rule patterns have different requirements:

**File labels** (`abac_label`, `abac_pair`):
- Stored in extended attributes, cached per-vnode
- May contain paths, descriptions, complex values
- 16 pairs × (64-byte key + 256-byte value) = 5KB per label
- Size is acceptable because labels are sparse (most files unlabeled)

**Rule patterns** (`abac_rule_pattern`, `abac_rule_pair`):
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
