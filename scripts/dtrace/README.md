# vLabel DTrace Scripts

This directory contains DTrace scripts for analyzing and debugging the vLabel MAC module.

## Prerequisites

- FreeBSD with DTrace support
- vLabel module loaded (`kldload mac_vlabel`)
- Root privileges

## Scripts

### Real-time Monitoring

| Script | Purpose |
|--------|---------|
| `vlabel-denials.d` | Watch access denials as they happen |
| `vlabel-transitions.d` | Watch label transitions on exec |
| `vlabel-all.d` | Trace ALL vLabel activity (verbose) |

### Performance Analysis

| Script | Purpose |
|--------|---------|
| `vlabel-latency.d` | Measure access check latency distribution |
| `vlabel-operations.d` | Count operations by type (read/write/exec) |
| `vlabel-hotspots.d` | Find most common access patterns |

### Policy Analysis

| Script | Purpose |
|--------|---------|
| `vlabel-rules.d` | Analyze rule matching frequency |
| `vlabel-labels.d` | Track label reads and defaults |

### Memory Analysis

| Script | Purpose |
|--------|---------|
| `vlabel-memory.d` | Track UMA zone allocations |

## Usage

```sh
# Watch denials
dtrace -s vlabel-denials.d

# Measure latency (run workload, then Ctrl+C for results)
dtrace -s vlabel-latency.d

# Find hotspots
dtrace -s vlabel-hotspots.d
```

## Quick One-liners

```sh
# Count denials by operation
dtrace -n 'vlabel:::check-deny { @[arg2] = count(); }'

# Watch rule additions
dtrace -n 'vlabel:::rule-add { printf("rule %u added\n", arg0); }'

# Measure average check time
dtrace -n 'vlabel:::check-entry { self->ts = timestamp; }
           vlabel:::check-return /self->ts/ {
               @avg = avg(timestamp - self->ts);
               self->ts = 0;
           }'
```

## Available Probes

| Probe | Arguments |
|-------|-----------|
| `vlabel:::check-entry` | subject, object, op |
| `vlabel:::check-return` | result, op |
| `vlabel:::check-allow` | subject, object, op, rule_id |
| `vlabel:::check-deny` | subject, object, op, rule_id |
| `vlabel:::rule-match` | rule_id, action, op |
| `vlabel:::rule-nomatch` | default_policy, op |
| `vlabel:::transition-exec` | old_label, new_label, exec_label, pid |
| `vlabel:::extattr-read` | label, vnode |
| `vlabel:::extattr-default` | is_subject |
| `vlabel:::rule-add` | rule_id, action, ops |
| `vlabel:::rule-remove` | rule_id |
| `vlabel:::rule-clear` | count |
| `vlabel:::mode-change` | old_mode, new_mode |

## Operation Masks

```
VLABEL_OP_READ    = 0x01
VLABEL_OP_WRITE   = 0x02
VLABEL_OP_EXEC    = 0x04
VLABEL_OP_OPEN    = 0x08
VLABEL_OP_STAT    = 0x10
VLABEL_OP_CREATE  = 0x20
VLABEL_OP_UNLINK  = 0x40
VLABEL_OP_LOOKUP  = 0x80
```
