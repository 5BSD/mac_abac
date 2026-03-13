# MAC ABAC Administrator Guide

This guide covers filesystem behavior, sysctls, syscalls, and security best practices for deploying MAC ABAC in production.

## Filesystem Behavior

MAC ABAC stores labels in extended attributes (`system:mac_abac`). The behavior differs between filesystems due to how FreeBSD's MAC framework interacts with them.

### UFS2 with Multilabel

UFS2 supports `MNT_MULTILABEL`, which enables full MAC framework integration.

**Enabling multilabel:**
```sh
tunefs -l enable /dev/ada0p2
mount -o multilabel /dev/ada0p2 /mnt
```

**Behavior:**
- Labels are read automatically when vnodes are created (`mpo_vnode_associate_extattr`)
- Standard MAC APIs (`setfmac`, `getfmac`) work if rules permit
- In-memory labels stay synchronized with on-disk labels

### ZFS (and Other Single-Label Filesystems)

ZFS does not support `MNT_MULTILABEL`. Extended attributes work, but the MAC framework treats it as a single-label filesystem.

**Behavior:**
- `mpo_vnode_associate_singlelabel` is called instead of `mpo_vnode_associate_extattr`
- Labels are still read from extended attributes at vnode creation time
- Standard MAC APIs (`setfmac`) return `EOPNOTSUPP`
- **You must use `mac_abac_ctl` or `mac_abacd` to set labels**

**Label Setting on ZFS:**
```sh
# This works (uses ABAC_SYS_SETLABEL syscall):
mac_abac_ctl label set /zfspool/file "type=secret"

# This does NOT work on ZFS:
setfmac mac_abac/type=secret /zfspool/file  # Returns EOPNOTSUPP
```

**Why ABAC_SYS_SETLABEL is Required:**

The syscall performs two operations atomically:
1. Writes label to extended attribute (on-disk)
2. Updates in-memory vnode label cache

Without this, using raw `setextattr` would update disk but not memory, causing stale label checks until the vnode is evicted from cache.

### tmpfs, nullfs, and Others

These filesystems typically don't support extended attributes. Files get the default label. Label persistence is not possible.

### Summary Table

| Filesystem | Extended Attrs | MNT_MULTILABEL | setfmac Works | mac_abac_ctl Works | Persistent |
|------------|---------------|----------------|---------------|-------------------|------------|
| UFS2 (multilabel) | Yes | Yes | Yes (with rules) | Yes | Yes |
| ZFS | Yes | No | No | Yes | Yes |
| tmpfs | No | No | No | No | No |
| nullfs | Passthrough | Passthrough | Depends | Depends | Depends |

---

## Sysctls

All sysctls are under `security.mac.mac_abac.*`:

### Core Configuration

| Sysctl | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | int | 1 | Master enable/disable switch |
| `mode` | int | 1 | Enforcement mode (see below) |
| `locked` | int (RO) | 0 | Policy lock status (1=locked until reboot) |

**Mode Values:**
- `0` = Disabled - No checks performed
- `1` = Permissive - Log violations but allow access
- `2` = Enforcing - Deny violations

```sh
# Check current mode
sysctl security.mac.mac_abac.mode

# Set enforcing mode
sysctl security.mac.mac_abac.mode=2
```

### Logging

| Sysctl | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | int | 2 | What to log to kernel message buffer |

**Log Levels:**
- `0` = None - No logging
- `1` = Error - Errors only
- `2` = Admin - Admin actions (rule/mode changes)
- `3` = Deny - Add access denials
- `4` = All - All access checks (very verbose)

```sh
# Log all denials
sysctl security.mac.mac_abac.log_level=3
```

### Statistics (Read-Only)

| Sysctl | Type | Description |
|--------|------|-------------|
| `labels_read` | uint64 | Labels successfully read from extattr |
| `labels_default` | uint64 | Times default label was assigned |

```sh
sysctl security.mac.mac_abac.labels_read security.mac.mac_abac.labels_default
```

### Extended Attribute Configuration

| Sysctl | Type | Default | Description |
|--------|------|---------|-------------|
| `extattr_name` | string | "mac_abac" | Name of extended attribute for labels |

**Warning:** Only change this at boot before loading rules. Changing while labels exist causes access issues.

```sh
# In /boot/loader.conf:
security.mac.mac_abac.extattr_name="mac_labels"
```

---

## Syscalls

All operations use `mac_syscall("mac_abac", command, arg)`. The `mac_abac_ctl` tool wraps these.

### Mode and Policy

| Command | Value | Arg Type | Description |
|---------|-------|----------|-------------|
| `ABAC_SYS_GETMODE` | 1 | `int*` (out) | Get current mode |
| `ABAC_SYS_SETMODE` | 2 | `int*` (in) | Set mode (0/1/2) |
| `ABAC_SYS_GETDEFPOL` | 6 | `int*` (out) | Get default policy (0=allow, 1=deny) |
| `ABAC_SYS_SETDEFPOL` | 7 | `int*` (in) | Set default policy |
| `ABAC_SYS_GETSTATS` | 5 | `struct abac_stats*` | Get statistics |

### Rule Management

| Command | Value | Arg Type | Description |
|---------|-------|----------|-------------|
| `ABAC_SYS_RULE_ADD` | 10 | `struct abac_rule_arg*` | Add a single rule |
| `ABAC_SYS_RULE_REMOVE` | 11 | `uint32_t*` (rule ID) | Remove rule by ID |
| `ABAC_SYS_RULE_CLEAR` | 12 | NULL | Clear all rules |
| `ABAC_SYS_RULE_LIST` | 13 | `struct abac_rule_list_arg*` | List rules |
| `ABAC_SYS_RULE_LOAD` | 14 | `struct abac_rule_load_arg*` | Atomic rule replace |

### Label Management

| Command | Value | Arg Type | Description |
|---------|-------|----------|-------------|
| `ABAC_SYS_SETLABEL` | 22 | `struct abac_setlabel_arg*` | Atomically set file label (disk + memory) |
| `ABAC_SYS_REFRESH` | 21 | `int*` (file descriptor) | Refresh in-memory label from disk |
| `ABAC_SYS_TEST` | 20 | `struct abac_test_arg*` | Test if access would be allowed |

**ABAC_SYS_SETLABEL** is the preferred method for setting labels. It:
1. Writes to extended attribute
2. Updates in-memory vnode cache
3. Does both atomically under vnode lock

### Rule Sets

| Command | Value | Arg Type | Description |
|---------|-------|----------|-------------|
| `ABAC_SYS_SET_ENABLE` | 23 | `struct abac_set_range*` | Enable rule sets |
| `ABAC_SYS_SET_DISABLE` | 24 | `struct abac_set_range*` | Disable rule sets |
| `ABAC_SYS_SET_SWAP` | 25 | `uint16_t[2]` | Atomic swap two sets |
| `ABAC_SYS_SET_MOVE` | 26 | `uint16_t[2]` | Move rules between sets |
| `ABAC_SYS_SET_CLEAR` | 27 | `uint16_t*` | Clear all rules in set |
| `ABAC_SYS_SET_LIST` | 28 | `struct abac_set_list_arg*` | List set status |

### Policy Protection

| Command | Value | Arg Type | Description |
|---------|-------|----------|-------------|
| `ABAC_SYS_LOCK` | 30 | NULL | Lock policy (one-way, until reboot) |
| `ABAC_SYS_GETLOCKED` | 31 | `int*` (out) | Check if locked |
| `ABAC_SYS_GETLOGLEVEL` | 32 | `int*` (out) | Get log level |
| `ABAC_SYS_SETLOGLEVEL` | 33 | `int*` (in) | Set log level |

---

## Security Best Practices

### Protecting Labels from Modification

**Critical:** Without proper rules, any process could modify labels using `setextattr(2)` directly. You must add rules to restrict label modification.

**Recommended Policy Pattern:**

```sh
# Create an admin label for processes that can modify labels
# (assigned via process label transition on exec)

# Only admin-labeled processes can modify label attributes
mac_abac_ctl rule add "allow setextattr type=admin -> *"

# Deny all other setextattr on system namespace (where labels live)
# This rule should be evaluated after the allow rule above
mac_abac_ctl rule add "deny setextattr * -> *"
```

**UCL Policy File:**
```
rules = [
    {
        id = 1
        action = "allow"
        operations = ["setextattr"]
        subject = { type = "admin" }
    }
    {
        id = 2
        action = "deny"
        operations = ["setextattr"]
    }
]
```

**Important Notes:**
- Rules are evaluated in order (first match wins)
- The allow rule must come before the deny rule
- The tool `mac_abac_ctl` uses the same `setextattr` path, so it needs the admin label
- Consider also protecting `getextattr` if label contents are sensitive

### Assigning Admin Labels

Admin tools need the `type=admin` label (or your chosen admin label). Options:

**Option 1: Label the binary**
```sh
mac_abac_ctl label set /usr/local/sbin/mac_abac_ctl "type=admin"
```

**Option 2: Use transition rules**
```sh
# When root executes mac_abac_ctl, transition to admin label
mac_abac_ctl rule add "transition exec * ctx:uid=0 -> path=/usr/local/sbin/mac_abac_ctl => type=admin"
```

### Production Deployment Checklist

1. **Start in permissive mode** - Test your policy without enforcement
   ```sh
   sysctl security.mac.mac_abac.mode=1
   ```

2. **Load your policy**
   ```sh
   mac_abac_ctl rule load /etc/mac_abac/policy.conf
   ```

3. **Label administrative tools**
   ```sh
   mac_abac_ctl label set /usr/local/sbin/mac_abac_ctl "type=admin"
   mac_abac_ctl label set /usr/local/sbin/mac_abacd "type=admin"
   ```

4. **Verify labels are protected**
   ```sh
   # As non-admin user, this should fail:
   setextattr system mac_abac "type=hacked" /some/file
   ```

5. **Enable enforcing mode**
   ```sh
   sysctl security.mac.mac_abac.mode=2
   ```

6. **Lock the policy** (optional, prevents changes until reboot)
   ```sh
   mac_abac_ctl lock
   ```

### Monitoring

**Watch denials in real-time:**
```sh
sysctl security.mac.mac_abac.log_level=3
tail -f /var/log/messages | grep ABAC
```

**Using DTrace:**
```sh
dtrace -s /usr/local/share/mac_abac/dtrace/abac-denials.d
```

**Check statistics:**
```sh
mac_abac_ctl stats
```

---

## Common Operations

### Setting Labels on ZFS

```sh
# Single file
mac_abac_ctl label set /zpool/data/file.txt "type=data,owner=user1"

# Recursive (directories)
mac_abac_ctl label setrecursive /zpool/data "type=data"

# Verify
mac_abac_ctl label get /zpool/data/file.txt
```

### Hot-Reloading Policy

Use rule sets for zero-downtime policy updates:

```sh
# Load new rules to inactive set 50000
mac_abac_ctl rule load -s 50000 /etc/mac_abac/new-policy.conf

# Atomically swap with active set 0
mac_abac_ctl set swap 0 50000

# Clear old rules from set 50000
mac_abac_ctl set clear 50000
```

### Emergency Recovery

If you lock yourself out:

1. Boot to single-user mode
2. Module loads but policy may not be loaded yet
3. Either:
   - Don't load the policy (rules are empty = default allow)
   - Load a permissive policy
   - Disable the module: `sysctl security.mac.mac_abac.enabled=0`

---

## Troubleshooting

### Labels Not Persisting on ZFS

**Symptom:** Labels disappear after reboot or vnode cache flush.

**Cause:** Using `setextattr` directly instead of `mac_abac_ctl`.

**Fix:** Always use `mac_abac_ctl label set` on ZFS.

### "Operation not supported" on setfmac

**Symptom:** `setfmac` returns EOPNOTSUPP on ZFS.

**Cause:** ZFS doesn't support MNT_MULTILABEL.

**Fix:** Use `mac_abac_ctl label set` instead.

### Rules Not Taking Effect

**Symptom:** Access allowed despite deny rules.

**Check:**
1. Is mode enforcing? `sysctl security.mac.mac_abac.mode`
2. Are rules loaded? `mac_abac_ctl rule list`
3. Is the rule set enabled? `mac_abac_ctl set list`
4. Test the rule: `mac_abac_ctl test exec "subject_label" "object_label"`

### Stale Labels After Manual extattr Edit

**Symptom:** Changed label via `setextattr` but access checks use old label.

**Fix:** Refresh the in-memory cache:
```sh
mac_abac_ctl label refresh /path/to/file
```

Or use `mac_abac_ctl label set` which does this atomically.
