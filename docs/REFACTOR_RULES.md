# vLabel Rule Storage Refactor Plan (v2)

## Problem

Current rule storage is extremely memory-inefficient. Each rule allocates fixed-size arrays for the maximum possible label/pattern size (16 pairs × 320 bytes each), regardless of actual content.

### Current struct sizes:

```
vlabel_pair    =  320 bytes  (64 key + 256 value)
vlabel_label   = 9224 bytes  (4096 raw + 8 metadata + 16×320 pairs)
vlabel_pattern = 5128 bytes  (8 metadata + 16×320 pairs)
vlabel_context =   24 bytes

vlabel_rule    = ~19 KB total
  - vr_subject (pattern):    5128 bytes
  - vr_object (pattern):     5128 bytes
  - vr_newlabel (label):     9224 bytes  (unused for non-transition rules!)
  - vr_subj_context:           24 bytes
  - vr_obj_context:            24 bytes
  - vr_id, vr_action, etc:     ~9 bytes
```

### Memory impact (current):

| Rules  | Memory   |
|--------|----------|
| 1,024  | 19 MB    |
| 4,096  | 76 MB    |
| 16,384 | 304 MB   |

### The waste:

A typical rule like `allow exec type=app -> *` uses:
- Subject pattern: 1 pair ("type=app")
- Object pattern: 0 pairs (wildcard)
- No transition label

But allocates: 19 KB

---

## Analysis: Real-World Usage

Examining examples.md, typical patterns use 1-4 pairs:

| Pattern Example | Pairs |
|-----------------|-------|
| `type=app` | 1 |
| `type=app,domain=web` | 2 |
| `layer=frontend,app=nginx,env=production` | 3 |
| `role=dba,region=us,env=production` | 3 |
| `clearance=topsecret,sci=true,indoc=current` | 3 |

**Conclusion:** 8 pairs covers all realistic rule patterns with headroom.

File labels can be longer (up to 16 pairs), but rule patterns are shorter.

---

## Solution: Option E - Pre-Parsed Binary with Reduced Limits

### Key Principles

1. **Separate limits for rules vs labels:**
   - Rule patterns: 8 pairs max (covers all realistic cases)
   - File labels: Keep 16 pairs (complex real labels need this)

2. **Parse in userland, not kernel:**
   - vlabelctl parses pattern strings
   - Kernel receives pre-parsed binary format
   - No string parsing in kernel hot paths

3. **Fixed-size rule struct:**
   - Uniform allocation size for UMA efficiency
   - No pointer arithmetic bugs
   - Pre-parsed data for fast matching

4. **Separate transition label allocation:**
   - Only allocate vr_newlabel when needed
   - Most rules aren't transitions

---

## New Data Structures

### Rule pattern (8 pairs max)

```c
/*
 * Compact key-value pair for rule patterns
 *
 * Smaller than vlabel_pair because rule patterns don't need
 * the same capacity as file labels.
 */
struct vlabel_rule_pair {
    char    vrp_key[32];      /* Pattern key */
    char    vrp_value[64];    /* Pattern value or "*" */
};

/*
 * Rule pattern - optimized for matching
 *
 * 8 pairs is sufficient for all realistic rule patterns.
 * File labels keep the full 16-pair vlabel_label struct.
 */
#define VLABEL_RULE_MAX_PAIRS   8

struct vlabel_rule_pattern {
    uint32_t                vp_flags;     /* VLABEL_MATCH_NEGATE */
    uint8_t                 vp_npairs;    /* Number of valid pairs */
    uint8_t                 vp_reserved[3];
    struct vlabel_rule_pair vp_pairs[VLABEL_RULE_MAX_PAIRS];
};
/* Size: 4 + 4 + (8 × 96) = 776 bytes */
```

### Rule structure (non-transition)

```c
struct vlabel_rule {
    uint32_t                 vr_id;
    uint8_t                  vr_action;
    uint8_t                  vr_reserved[3];
    uint32_t                 vr_operations;
    struct vlabel_rule_pattern vr_subject;   /* 776 bytes */
    struct vlabel_rule_pattern vr_object;    /* 776 bytes */
    struct vlabel_context    vr_subj_context; /* 24 bytes */
    struct vlabel_context    vr_obj_context;  /* 24 bytes */
    struct vlabel_label     *vr_newlabel;    /* NULL or allocated */
};
/* Size: ~1,612 bytes (non-transition) */
```

### Memory impact (new):

| Rules  | Current | New      | Savings |
|--------|---------|----------|---------|
| 1,024  | 19 MB   | 1.6 MB   | 12x     |
| 4,096  | 76 MB   | 6.3 MB   | 12x     |
| 8,192  | 152 MB  | 12.5 MB  | 12x     |
| 16,384 | 304 MB  | 25 MB    | 12x     |

---

## Userland API Changes

### Current flow (redundant parsing):

```
User: "type=app,domain=web"
         |
         v
vlabelctl parses to vlabel_rule_io    <- parsing #1
         |
         v
Kernel parses into vlabel_pattern     <- parsing #2 (wasteful)
         |
         v
Stored as pre-parsed pairs
```

### New flow (parse once in userland):

```
User: "type=app,domain=web"
         |
         v
vlabelctl parses to vlabel_rule_arg   <- parsing (once)
  with embedded vlabel_rule_pattern
         |
         v
Kernel validates and copies directly  <- no parsing
         |
         v
Store in rule struct
```

### New syscall argument structure

```c
/*
 * Rule pattern for syscall - matches kernel struct exactly
 */
struct vlabel_rule_pattern_arg {
    uint32_t    vp_flags;
    uint8_t     vp_npairs;
    uint8_t     vp_reserved[3];
    struct {
        char    key[32];
        char    value[64];
    } vp_pairs[8];
};

/*
 * Rule add argument - fixed size, pre-parsed
 *
 * vlabelctl parses pattern strings and fills this structure.
 * Kernel just validates and copies.
 */
struct vlabel_rule_arg_v2 {
    uint32_t    vr_id;          /* Out: assigned rule ID */
    uint8_t     vr_action;      /* ALLOW/DENY/TRANSITION */
    uint8_t     vr_has_newlabel; /* 1 if transition rule */
    uint8_t     vr_reserved[2];
    uint32_t    vr_operations;
    struct vlabel_rule_pattern_arg vr_subject;
    struct vlabel_rule_pattern_arg vr_object;
    struct vlabel_context_arg vr_subj_context;
    struct vlabel_context_arg vr_obj_context;
    /* For transitions: newlabel follows as variable data */
    uint16_t    vr_newlabel_len;  /* 0 if not transition */
    uint16_t    vr_reserved2;
    /* char newlabel[vr_newlabel_len] follows */
};
```

---

## Implementation Plan

### Phase 0: Documentation (Do First)

Before changing code, document the current and target state:

1. **Man pages:**
   - `vlabelctl.8` - Administration tool usage
   - `mac_vlabel.4` - Kernel module overview
   - `vlabel.conf.5` - Policy file format

2. **Update architecture.md:**
   - Current memory usage analysis
   - New struct layouts and sizes
   - Parsing flow (before/after)
   - Syscall API changes

3. **Inline documentation:**
   - Add rationale comments for all limits in mac_vlabel.h
   - Document why 8 pairs per pattern is sufficient
   - Document why 16 pairs per label is needed

See `KERNEL_AUDIT.md` for full analysis of what should move to userland.

### Phase 1: Fix Critical Bug

Fix stack overflow in `vlabel_rules_load()`:

```c
/* CURRENT - will panic with 4K+ rules */
struct vlabel_rule *old_rules[VLABEL_MAX_RULES];

/* FIXED - dynamic allocation */
struct vlabel_rule **old_rules;
old_rules = malloc(sizeof(struct vlabel_rule *) * vlabel_rule_end,
    M_TEMP, M_WAITOK);
if (old_rules == NULL)
    return (ENOMEM);
/* ... use old_rules ... */
free(old_rules, M_TEMP);
```

### Phase 2: Add New Structures

1. Add `struct vlabel_rule_pair` to mac_vlabel.h
2. Add `struct vlabel_rule_pattern` (8-pair version)
3. Add `struct vlabel_rule_arg_v2` for new syscall format
4. Keep old structures for compatibility during transition

### Phase 3: Update vlabelctl

1. Add pattern parsing to fill `vlabel_rule_pattern_arg`
2. Build `vlabel_rule_arg_v2` with pre-parsed data
3. Use new syscall format (version negotiation)

### Phase 4: Update Kernel

1. Add new syscall handler for v2 format
2. Update `vlabel_rule_add_from_arg()` to accept pre-parsed data
3. No kernel-side pattern parsing needed

### Phase 5: Update Matching

1. Modify `vlabel_pattern_match()` to use new struct
2. Direct struct comparison (no string parsing)
3. Fast path for common cases

### Phase 6: Transition Label Handling

For TRANSITION rules:
```c
if (arg->vr_action == VLABEL_ACTION_TRANSITION &&
    arg->vr_newlabel_len > 0) {
    rule->vr_newlabel = malloc(sizeof(struct vlabel_label),
        M_VLABEL, M_WAITOK | M_ZERO);
    /* Parse newlabel string (still needed for file label format) */
    vlabel_label_parse(newlabel_str, newlabel_len, rule->vr_newlabel);
}
```

### Phase 7: Increase Limits

```c
#define VLABEL_MAX_RULES    4096   /* Phase 1: conservative */
/* Later: 8192 or 16384 after testing */
```

---

## Files to Modify

| File | Changes |
|------|---------|
| mac_vlabel.h | New vlabel_rule_pattern, vlabel_rule_pair structs |
| mac_vlabel.h | New VLABEL_RULE_MAX_PAIRS limit (8) |
| mac_vlabel.h | New syscall arg struct (v2) |
| vlabel_syscall.c | Fix old_rules stack overflow |
| vlabel_syscall.c | New rule add handler for v2 |
| vlabel_match.c | Update to use new pattern struct |
| vlabel_rules.c | Update rule iteration (minimal) |
| vlabelctl_rule.c | Parse patterns into binary format |
| vlabelctl.h | Add pattern parsing functions |

---

## Compatibility Strategy

1. **Syscall versioning:** Add VLABEL_SYS_RULE_ADD_V2 (new number)
2. **Deprecate old API:** Keep VLABEL_SYS_RULE_ADD working for transition
3. **vlabelctl detection:** Try v2, fall back to v1 if ENOSYS

---

## Testing Checklist

- [ ] Existing test suite passes
- [ ] Rule add with 1-8 pairs works
- [ ] Rule add with >8 pairs rejected with clear error
- [ ] Transition rules allocate/free newlabel correctly
- [ ] Rule load with 4K rules doesn't panic
- [ ] Pattern matching performance unchanged
- [ ] Memory usage reduced as expected (check with vmstat -m)
- [ ] vlabelctl handles errors gracefully
- [ ] Man pages render correctly (man ./vlabelctl.8)
- [ ] mandoc -Tlint passes on all man pages

---

## Questions Resolved

| Question | Decision |
|----------|----------|
| Max pairs per rule pattern | 8 |
| Max pairs per file label | 16 (unchanged) |
| Where to parse | Userland (vlabelctl) |
| Cache parsed patterns? | Yes, in rule struct (pre-parsed) |
| Single vs separate allocation | Single for rule, separate for newlabel |
| M_VLABEL malloc type | Yes, add for tracking |

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| 8 pairs too few | Analysis shows max 6 in examples; can increase later |
| Userland parsing errors | Better than kernel panic; clear error messages |
| API compatibility | Version negotiation, graceful fallback |
| Transition label leaks | Single deallocation point in vlabel_rule_free() |

---

## Memory Tracking

Add dedicated malloc type:

```c
static MALLOC_DEFINE(M_VLABEL, "vlabel", "vLabel MAC policy");
```

Check with:
```sh
vmstat -m | grep vlabel
```
