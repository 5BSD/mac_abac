# vLabel Kernel Code Audit

## Overview

This document audits the kernel code for operations that should be moved to userland, redundant code, and potential issues.

---

## Category 1: Parsing That Should Move to Userland

### 1.1 Pattern Parsing in Rule Add (MOVE)

**Location:** `vlabel_syscall.c:85-113`, `vlabel_syscall.c:215-240`

```c
/* Current: kernel parses pattern strings */
error = vlabel_pattern_parse(subject_str, strlen(subject_str),
    &newrule->vr_subject);
```

**Problem:**
- Duplicates parsing already done in vlabelctl
- String operations in kernel are expensive
- Error messages less helpful than userland

**Solution:** Move to userland. Kernel receives pre-parsed `vlabel_rule_pattern_arg`.

### 1.2 Format Conversion in Rule Add (MOVE)

**Location:** `vlabel_syscall.c:134`, `vlabel_syscall.c:259`

```c
vlabel_convert_label_format(newlabel_str, converted, VLABEL_MAX_LABEL_LEN);
```

**Problem:**
- Converting comma-separated → newline-separated
- This is purely a CLI convenience, doesn't belong in kernel

**Solution:** vlabelctl should send labels in canonical format (newline-separated).

### 1.3 Test Access Parsing (MOVE)

**Location:** `vlabel_syscall.c:583-591`

```c
vlabel_convert_label_format(subject, converted, VLABEL_MAX_LABEL_LEN);
vlabel_label_parse(converted, strlen(converted), subj_label);
```

**Problem:**
- Test command parses label strings in kernel
- Same pattern as rule add

**Solution:** Pre-parse in vlabelctl, send binary struct.

---

## Category 2: Parsing That MUST Stay in Kernel

### 2.1 Extended Attribute Label Parsing (KEEP)

**Location:** `vlabel_vnode.c:149`

```c
error = vlabel_label_parse(buf, buflen, vl);
```

**Reason:** Labels stored on disk are strings. Kernel must parse them when reading from extattrs. No way around this.

**Optimization possible:**
- Labels on disk are already newline-separated
- No format conversion needed
- Current code is optimal

### 2.2 Credential Internalize (KEEP)

**Location:** `vlabel_cred.c:155`

```c
error = vlabel_label_parse(converted, strlen(converted), vl);
```

**Reason:** MAC framework's internalize callback receives strings from procfs/sysctl. Must parse in kernel.

**Note:** Format conversion here (comma → newline) is needed because user input comes as comma-separated.

---

## Category 3: Redundant Code

### 3.1 Duplicate Rule Add Functions

**Location:** `vlabel_syscall.c:48-181` and `vlabel_syscall.c:186-290`

Two nearly identical functions:
- `vlabel_rule_add_from_arg()` - acquires lock
- `vlabel_rule_add_locked()` - assumes lock held

**~200 lines of duplication.**

**Solution:** Extract common code into helper, or make one call the other.

### 3.2 Pattern to String (Rarely Used)

**Location:** `vlabel_match.c:262-310` - `vlabel_pattern_to_string()`

Only used for rule serialization in `vlabel_rule_serialize()`.

**Suggestion:** Keep, but consider if listing rules should be simpler (just store original string alongside parsed data).

---

## Category 4: Allocations in Hot Paths

### 4.1 Conversion Buffer Allocation

**Location:** `vlabel_syscall.c:72`, `vlabel_syscall.c:204`, `vlabel_syscall.c:579`

```c
converted = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);
```

**Problem:** Allocates 4KB buffer for format conversion every time.

**Solution:** When parsing moves to userland, this goes away entirely.

### 4.2 Test Access Allocations

**Location:** `vlabel_syscall.c:577-579`

```c
subj_label = malloc(sizeof(*subj_label), M_TEMP, M_WAITOK | M_ZERO);
obj_label = malloc(sizeof(*obj_label), M_TEMP, M_WAITOK | M_ZERO);
converted = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK);
```

**Problem:** Three allocations per test call. ~20KB total.

**Solution:** Pre-parse in userland, receive binary structs.

---

## Category 5: Correct But Could Be Simpler

### 5.1 UMA Zone for Labels

**Location:** `vlabel_label.c:33`, `vlabel_label.c:59`

```c
static uma_zone_t vlabel_zone;
vlabel_zone = uma_zcreate("vlabel_label", sizeof(struct vlabel_label), ...);
```

**Status:** CORRECT. Using UMA for labels is the right choice:
- Labels are ~9KB each
- Frequently allocated/freed (every vnode, cred)
- UMA provides efficient caching

### 5.2 Extattr Read Buffer

**Location:** `vlabel_vnode.c:109`

```c
buf = malloc(VLABEL_MAX_LABEL_LEN, M_TEMP, M_WAITOK | M_ZERO);
```

**Status:** CORRECT. Must allocate buffer to read extattr. Can't avoid this.

**Possible optimization:** Use stack buffer for common case (small labels), fall back to malloc for large.

---

## Category 6: Documentation Gaps

### 6.1 No Man Pages

Missing:
- `vlabelctl(8)` - administration tool
- `mac_vlabel(4)` - kernel module
- `vlabel.conf(5)` - policy file format

### 6.2 No Architecture Doc Updates

`docs/architecture.md` needs update for:
- New struct sizes
- Memory usage calculations
- Parsing flow changes

### 6.3 No Inline Docs for Limits

The limit values (8 pairs, 4K rules, etc.) should be documented inline in `mac_vlabel.h` with rationale.

---

## Summary: What Should Move to Userland

| Operation | Current Location | Move To |
|-----------|------------------|---------|
| Pattern parsing (rules) | vlabel_syscall.c | vlabelctl |
| Format conversion (comma→newline) | vlabel_syscall.c | vlabelctl |
| Test access label parsing | vlabel_syscall.c | vlabelctl |
| Rule validation | kernel + vlabelctl | vlabelctl only |

## What Must Stay in Kernel

| Operation | Reason |
|-----------|--------|
| Extattr label parsing | Labels on disk are strings |
| Credential internalize | MAC framework callback |
| Pattern matching | Hot path, must be fast |
| Rule evaluation | Security-critical |

---

## Action Items

1. **Phase 0 (Documentation):**
   - [ ] Write man pages (vlabelctl.8, mac_vlabel.4, vlabel.conf.5)
   - [ ] Update architecture.md with new design
   - [ ] Add limit rationale comments to mac_vlabel.h

2. **Phase 1 (Critical Bug):**
   - [ ] Fix stack overflow in vlabel_rules_load()

3. **Phase 2 (Remove Kernel Parsing):**
   - [ ] Add pre-parsed syscall structs
   - [ ] Update vlabelctl to parse and pack binary
   - [ ] Remove vlabel_pattern_parse() calls from syscall handlers
   - [ ] Remove vlabel_convert_label_format() from syscall handlers

4. **Phase 3 (Cleanup):**
   - [ ] Deduplicate vlabel_rule_add_from_arg() / vlabel_rule_add_locked()
   - [ ] Add M_VLABEL malloc type
   - [ ] Review allocation patterns

---

## Risk: Keeping Pattern Parsing in Kernel

If we DON'T move parsing to userland:

| Risk | Impact |
|------|--------|
| Kernel panic on malformed input | High (security) |
| Complex error handling in kernel | Medium (maintainability) |
| Larger kernel attack surface | Medium (security) |
| Duplicate code with vlabelctl | Low (maintenance) |

Recommendation: **Move parsing to userland.** Kernel should only receive validated, pre-parsed binary data.
