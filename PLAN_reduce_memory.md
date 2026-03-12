# Plan: Reduce mac_abac Memory Consumption

## Overview
Reduce per-label memory from ~9.2KB to ~5.1KB by removing redundant storage and dead code.

## Changes

### 1. Remove `vl_raw` from `struct abac_label`

**File:** `kernel/mac_abac.h`

**Current struct (~9.2KB):**
```c
struct abac_label {
    char            vl_raw[ABAC_MAX_LABEL_LEN];  // 4096 bytes - REMOVE
    uint32_t        vl_hash;                      //    4 bytes
    uint32_t        vl_npairs;                    //    4 bytes
    struct abac_pair vl_pairs[ABAC_MAX_PAIRS];    // 5120 bytes
};
```

**New struct (~5.1KB):**
```c
struct abac_label {
    uint32_t        vl_hash;                      //    4 bytes
    uint32_t        vl_npairs;                    //    4 bytes
    struct abac_pair vl_pairs[ABAC_MAX_PAIRS];    // 5120 bytes
};
```

**Files to update:**
- `kernel/mac_abac.h` - Remove vl_raw from struct
- `kernel/abac_label.c` - Update abac_label_parse() to not store raw
- `kernel/abac_label.c` - Update abac_label_set_default() to not use vl_raw
- `kernel/abac_label.c` - Update abac_label_to_string() to reconstruct from pairs
- `kernel/abac_cred.c` - Update any vl_raw references (externalize_label)
- `kernel/abac_vnode.c` - Update DTrace probes that use vl_raw

### 2. Remove dead `struct abac_pattern` and related functions

**File:** `kernel/mac_abac.h`
- Remove `struct abac_pattern` definition (lines 533-537)
- Remove `abac_label_match()` prototype
- Remove `abac_pattern_match()` prototype
- Remove `abac_pattern_parse()` prototype
- Remove `abac_pattern_to_string()` prototype

**File:** `kernel/abac_label.c`
- Remove `abac_label_match()` function
- Remove `abac_pattern_parse()` function

**File:** `kernel/abac_match.c`
- Remove `abac_pattern_match()` function
- Remove `abac_pattern_to_string()` function

### 3. Update code that references vl_raw

**abac_cred.c:abac_cred_externalize_label():**
- Currently reads `vl->vl_raw` directly
- Change to call `abac_label_to_string()` into a stack buffer

**abac_vnode.c DTrace probes:**
- SDT_PROBE that uses `vl->vl_raw`
- Change to call `abac_label_to_string()` or use first pair

**abac_cred.c:abac_execve_transition() DTrace:**
- Uses `oldvl->vl_raw`, `newvl->vl_raw`, `objvl->vl_raw`
- Change to reconstruct strings for DTrace

### 4. Update abac_label_to_string()

Current implementation just copies vl_raw. New implementation must reconstruct:

```c
int
abac_label_to_string(const struct abac_label *vl, char *buf, size_t buflen)
{
    size_t pos = 0;
    uint32_t i;

    if (vl == NULL || buf == NULL || buflen == 0)
        return (-1);

    buf[0] = '\0';

    for (i = 0; i < vl->vl_npairs && pos < buflen - 1; i++) {
        int written = snprintf(buf + pos, buflen - pos, "%s=%s\n",
            vl->vl_pairs[i].vp_key, vl->vl_pairs[i].vp_value);
        if (written < 0 || (size_t)written >= buflen - pos)
            return (-1);
        pos += written;
    }

    return ((int)pos);
}
```

## Memory Impact

| Metric | Before | After |
|--------|--------|-------|
| Per-label size | 9,224 bytes | 5,128 bytes |
| 288 labels | 2.6 MB | 1.5 MB |
| Reduction | - | 44% |

## Testing

1. Build kernel module
2. Load module
3. Run existing test suite
4. Verify labels read from extattr correctly
5. Verify labels written to extattr correctly
6. Verify DTrace probes still work
7. Check memory stats via sysctl

## Future Considerations (not in this plan)

- Reduce ABAC_MAX_SETS from 65536 to 256 (saves 8KB global)
- Reduce ABAC_MAX_PAIRS from 16 to 8
- Reduce ABAC_MAX_VALUE_LEN from 256 to 128
