# ABAC DTrace Scripts

This directory contains DTrace scripts for analyzing and debugging the ABAC MAC module.

## Prerequisites

- FreeBSD with DTrace support
- ABAC module loaded (`kldload mac_abac`)
- Root privileges

## Scripts

### Real-time Monitoring

| Script | Purpose |
|--------|---------|
| `abac-denials.d` | Watch access denials as they happen |
| `abac-transitions.d` | Watch label transitions on exec |
| `abac-all.d` | Trace ALL ABAC activity (verbose) |

### Performance Analysis

| Script | Purpose |
|--------|---------|
| `abac-latency.d` | Measure access check latency distribution |
| `abac-operations.d` | Count operations by type (read/write/exec) |
| `abac-hotspots.d` | Find most common access patterns |

### Policy Analysis

| Script | Purpose |
|--------|---------|
| `abac-rules.d` | Analyze rule matching frequency |
| `abac-labels.d` | Track label reads and defaults |

### Memory Analysis

| Script | Purpose |
|--------|---------|
| `abac-memory.d` | Track UMA zone allocations |

## Usage

```sh
# Watch denials
dtrace -s abac-denials.d

# Measure latency (run workload, then Ctrl+C for results)
dtrace -s abac-latency.d

# Find hotspots
dtrace -s abac-hotspots.d
```

## Quick One-liners

```sh
# Count denials by operation
dtrace -n 'abac:::check-deny { @[arg2] = count(); }'

# Watch rule additions
dtrace -n 'abac:::rule-add { printf("rule %u added\n", arg0); }'

# Measure average check time
dtrace -n 'abac:::check-entry { self->ts = timestamp; }
           abac:::check-return /self->ts/ {
               @avg = avg(timestamp - self->ts);
               self->ts = 0;
           }'
```

## Available Probes

| Probe | Arguments |
|-------|-----------|
| `abac:::check-entry` | subject, object, op |
| `abac:::check-return` | result, op |
| `abac:::check-allow` | subject, object, op, rule_id |
| `abac:::check-deny` | subject, object, op, rule_id |
| `abac:::rule-match` | rule_id, action, op |
| `abac:::rule-nomatch` | default_policy, op |
| `abac:::transition-exec` | old_label, new_label, exec_label, pid |
| `abac:::extattr-read` | label, vnode |
| `abac:::extattr-default` | is_subject |
| `abac:::rule-add` | rule_id, action, ops |
| `abac:::rule-remove` | rule_id |
| `abac:::rule-clear` | count |
| `abac:::mode-change` | old_mode, new_mode |

## Operation Masks

```
ABAC_OP_READ    = 0x01
ABAC_OP_WRITE   = 0x02
ABAC_OP_EXEC    = 0x04
ABAC_OP_OPEN    = 0x08
ABAC_OP_STAT    = 0x10
ABAC_OP_CREATE  = 0x20
ABAC_OP_UNLINK  = 0x40
ABAC_OP_LOOKUP  = 0x80
```
