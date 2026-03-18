# mac_abac TODO

## Feature Requests

### 1. Set Declarations in Rule Files

**Status**: Not implemented

Allow set declarations at the top of rule files instead of per-rule `set N` suffix.

**Syntax**:
```
set              # "any" - daemon picks an available set
set 5            # All following rules go to set 5

allow read type=app -> type=data
allow write type=app -> type=data

set 10           # Switch to set 10
deny exec type=untrusted -> *
```

**Implementation**:
- Modify `daemon/parse_line.c` to track current set as parser state
- `set` alone = mark rules for caller-determined set
- `set N` = all following rules go to set N
- Per-rule `set N` suffix still overrides

---

### 2. MAC Syscall Protection with Rules

**Status**: Not implemented - only `priv_check(PRIV_MAC_PARTITION)` gates syscalls

ABAC's own control syscalls should be protected by rules, not just root check.

**New Operations**:
| Operation | Protects |
|-----------|----------|
| `policy_read` | GETSTATS, RULE_LIST, GETMODE, GETLOCKED, etc. |
| `policy_modify` | RULE_ADD, RULE_REMOVE, SETMODE, SET_*, SETDEFPOL |
| `policy_lock` | LOCK (one-way lock) |

**Rule Syntax** (subject-only, no object):
```
allow policy_modify type=policy_admin
allow policy_modify type=admin ctx:uid=0
deny policy_modify *

allow policy_read type=admin,type=auditor
allow policy_lock type=security_officer
```

**Implementation**:
- Add `ABAC_OP_POLICY_READ`, `ABAC_OP_POLICY_MODIFY`, `ABAC_OP_POLICY_LOCK` to `mac_abac.h`
- Add `abac_rules_check_subject_only()` function
- In `abac_syscall()`, before the switch:
  ```c
  uint32_t op = abac_syscall_to_op(call);
  if (op != 0) {
      subj = SLOT(td->td_ucred->cr_label);
      error = abac_rules_check_subject_only(td->td_ucred, subj, op);
      if (error)
          return (error);
  }
  ```

---

### 3. Query Process Label

**Status**: Not implemented

Add ability to query a process's ABAC label by PID.

**Syscall**: `ABAC_SYS_GETPROCLABEL`

**Argument Structure**:
```c
struct abac_getproclabel_arg {
    pid_t   vgp_pid;        /* Process to query */
    size_t  vgp_buflen;     /* Size of output buffer */
    size_t  vgp_labellen;   /* Output: actual label length */
    /* Followed by: char label[vgp_buflen] */
};
```

**Implementation**:
```c
case ABAC_SYS_GETPROCLABEL:
    error = copyin(arg, &getlabel_arg, sizeof(getlabel_arg));
    if (error) break;

    p = pfind(getlabel_arg.vgp_pid);
    if (p == NULL) { error = ESRCH; break; }

    /* Check if caller can see this process */
    error = p_cansee(td, p);
    if (error) { PROC_UNLOCK(p); break; }

    subj = SLOT(p->p_ucred->cr_label);
    if (subj == NULL) subj = &abac_default_subject;

    len = abac_label_to_string(subj, kbuf, getlabel_arg.vgp_buflen);
    getlabel_arg.vgp_labellen = len;

    PROC_UNLOCK(p);

    error = copyout(&getlabel_arg, arg, sizeof(getlabel_arg));
    if (error == 0 && len > 0)
        error = copyout(kbuf, (char *)arg + sizeof(getlabel_arg), len);
    break;
```

**CLI**: `mac_abac_ctl label pid <pid>`

**Protection**: Gated by rules - requires `policy_read` or `proc_getlabel` permission.
```
allow proc_getlabel type=admin
allow proc_getlabel type=auditor
deny proc_getlabel *
```

This makes label visibility itself a policy decision.

---

### 4. Subject-Only Rule Matching

**Status**: Partial - system operations use synthetic `type=system` object

For syscall gating and other subject-only checks, support rules without objects.

**Current Workaround**:
```
deny kld type=untrusted -> type=system
```

**Proposed Clean Syntax**:
```
# No arrow, no object - subject-only
allow policy_modify type=admin
deny policy_modify *
```

**Implementation**:
- Add `ABAC_RULE_FLAG_SUBJECT_ONLY` flag
- Parser detects rules without `->`
- `abac_rules_check_subject_only()` skips object matching

---

## Notes

- Set declarations should be backward compatible (per-rule `set N` still works)
- Syscall protection rules should be evaluated before `priv_check()` or replace it
- Process label query needs visibility check (`p_cansee()`) for security
