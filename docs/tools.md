# vLabel Tools Reference

## vlabelctl

Command-line utility for managing vLabel: labels, rules, statistics, and monitoring.

### Synopsis

```
vlabelctl <command> [arguments]
```

### Commands

#### mode

Get or set the enforcement mode.

```sh
# Get current mode
vlabelctl mode

# Set mode
vlabelctl mode disabled
vlabelctl mode permissive
vlabelctl mode enforcing
```

Modes:
- `disabled` - Module inactive, all operations allowed
- `permissive` - Rules evaluated and logged, never denied
- `enforcing` - Rules actively enforced

#### audit

Get or set the audit verbosity level.

```sh
# Get current level (not yet implemented)
vlabelctl audit

# Set level
vlabelctl audit none
vlabelctl audit denials
vlabelctl audit decisions
vlabelctl audit verbose
```

Levels:
- `none` - No audit logging
- `denials` - Log denied operations only
- `decisions` - Log all allow/deny decisions
- `verbose` - Full debug output

#### stats

Display module statistics.

```sh
vlabelctl stats
```

Output:
```
vLabel Statistics:
  Access checks:    1234
  Allowed:          1200
  Denied:           34
  Labels read:      567
  Default labels:   89
  Active rules:     12
```

#### limits

Display kernel limits and supported operations.

```sh
vlabelctl limits
```

Output:
```
vLabel Kernel Limits:
  Max label length:     4096 bytes
  Max key length:       64 bytes
  Max value length:     256 bytes
  Max key-value pairs:  16
  Max rules:            1024

Supported Operations:
  exec, read, write, mmap, link, rename, unlink,
  chdir, stat, readdir, create, setextattr, getextattr,
  lookup, open, access, debug, signal, sched, all

Rule Syntax:
  action operations subject -> object [=> newlabel]

  Actions: allow, deny, transition
  Operations: comma-separated list or 'all'
  Subject/Object: label pattern or '*' for any
  Newlabel: required for transition rules
```

#### rule

Manage access control rules.

```sh
# Add a rule (line format)
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule add "allow read,write domain=web -> domain=web"

# Remove a rule by ID
vlabelctl rule remove 5

# Clear all rules
vlabelctl rule clear
```

Line format:
```
action operations subject -> object
```

- `action`: `allow`, `deny`, or `transition`
- `operations`: Comma-separated list or `all`
- `subject`: Pattern for process label, or `*` for any
- `object`: Pattern for file label, or `*` for any

Examples:
```sh
vlabelctl rule add "deny exec * -> type=untrusted"
vlabelctl rule add "allow all type=trusted -> *"
vlabelctl rule add "allow read,write,open domain=web -> domain=web"
```

#### label

Manage file labels via extended attributes.

```sh
# Get a file's label
vlabelctl label get /path/to/file

# Set a file's label
vlabelctl label set /path/to/file "type=trusted,domain=system"

# Remove a file's label
vlabelctl label remove /path/to/file
```

Examples:
```sh
$ vlabelctl label get /usr/local/bin/myapp
type=app,domain=web

$ vlabelctl label set /tmp/download.sh "type=untrusted"
label set on /tmp/download.sh

$ vlabelctl label get /bin/ls
(no label)
```

#### monitor

Watch audit events in real-time.

```sh
vlabelctl monitor
```

Output:
```
Monitoring vLabel audit events (Ctrl+C to stop)...

[14:23:01] DENY op=0x0001 pid=1234 uid=1000 subj=type=user obj=type=untrusted path=/tmp/bad.sh
[14:23:05] ALLOW op=0x0002 pid=1235 uid=0 subj=type=trusted obj=type=system path=/etc/passwd
```

Fields:
- Timestamp
- ALLOW/DENY
- Operation bitmask
- Process ID
- User ID
- Subject label
- Object label
- File path (if available)

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 64 | Usage error |
| 69 | Module not loaded (mac_syscall failed) |
| 71 | System error |
| 77 | Permission denied |

---

## vlabeld

Policy daemon that loads rules from configuration files and monitors audit events.

### Synopsis

```
vlabeld [-dfv] [-c config] [-p pidfile]
vlabeld -t [-v] [-c config]
```

### Options

| Option | Description |
|--------|-------------|
| `-c config` | Policy configuration file (default: `/usr/local/etc/vlabel/policy.conf`) |
| `-d` | Debug mode: don't daemonize, verbose logging |
| `-f` | Foreground: don't daemonize |
| `-p pidfile` | PID file path (default: `/var/run/vlabeld.pid`) |
| `-t` | Test mode: validate config and exit |
| `-v` | Verbose output |

### Configuration File

See [Policy Language](policy.md) for full syntax.

Example `/usr/local/etc/vlabel/policy.conf`:
```json
{
    "mode": "enforcing",
    "audit": "denials",
    "rules": [
        {
            "id": 1,
            "action": "deny",
            "operations": ["exec"],
            "object": { "type": "untrusted" }
        },
        {
            "id": 100,
            "action": "allow",
            "operations": ["all"],
            "subject": { "type": "trusted" }
        }
    ]
}
```

### Usage Examples

#### Test Configuration

```sh
# Validate syntax without loading
vlabeld -t -c /etc/vlabel/policy.conf

# Verbose validation
vlabeld -t -v -c /etc/vlabel/policy.conf
```

Output:
```
loading policy from /etc/vlabel/policy.conf
parsing UCL file: /etc/vlabel/policy.conf
setting mode to enforcing (2)
setting audit level to denials (1)
  rule 1: action=1 ops=0x1 subj_flags=0x0 obj_flags=0x1
validated rule 1: action=1 ops=0x1
  rule 100: action=0 ops=0xffff subj_flags=0x1 obj_flags=0x0
validated rule 100: action=0 ops=0xffff
loaded 2 rules (0 errors)
policy loaded successfully
configuration OK
```

#### Run as Daemon

```sh
# Start daemon
vlabeld -c /etc/vlabel/policy.conf

# Check it's running
cat /var/run/vlabeld.pid

# View logs
tail -f /var/log/messages | grep vlabeld
```

#### Run in Foreground (Debug)

```sh
vlabeld -d -c /etc/vlabel/policy.conf
```

This runs in the foreground with verbose logging to stderr.

#### Reload Policy

Send SIGHUP to reload the configuration file:

```sh
kill -HUP $(cat /var/run/vlabeld.pid)
```

Or:
```sh
service vlabeld reload  # If rc.d script installed
```

### Signals

| Signal | Action |
|--------|--------|
| SIGHUP | Reload policy file |
| SIGTERM | Graceful shutdown |
| SIGINT | Graceful shutdown |

### Logging

When daemonized, logs to syslog facility `LOG_SECURITY`:
```
Mar  6 14:30:00 host vlabeld[1234]: loading policy from /etc/vlabel/policy.conf
Mar  6 14:30:00 host vlabeld[1234]: loaded 12 rules (0 errors)
Mar  6 14:30:01 host vlabeld[1234]: [2024-03-06 14:30:01] DENY pid=5678 uid=1000 ...
```

When running with `-d` or `-f`, logs to stderr.

### rc.d Script

Example `/usr/local/etc/rc.d/vlabeld`:

```sh
#!/bin/sh

# PROVIDE: vlabeld
# REQUIRE: FILESYSTEMS
# BEFORE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="vlabeld"
rcvar="vlabeld_enable"
command="/usr/local/sbin/vlabeld"
pidfile="/var/run/vlabeld.pid"

load_rc_config $name
: ${vlabeld_enable:="NO"}
: ${vlabeld_config:="/usr/local/etc/vlabel/policy.conf"}
: ${vlabeld_flags:="-c ${vlabeld_config}"}

run_rc_command "$1"
```

Enable in `/etc/rc.conf`:
```sh
vlabeld_enable="YES"
vlabeld_config="/usr/local/etc/vlabel/policy.conf"
```

---

## FreeBSD Native Tools

### setextattr / getextattr

Set and get extended attributes directly:

```sh
# Set label
setextattr system vlabel "type=trusted,domain=system" /path/to/file

# Get label
getextattr system vlabel /path/to/file

# Get label (quiet, value only)
getextattr -q system vlabel /path/to/file

# Remove label
rmextattr system vlabel /path/to/file
```

### sysctl

Direct kernel parameter access:

```sh
# View all vLabel sysctls
sysctl security.mac.vlabel

# Set mode
sysctl security.mac.vlabel.mode=2

# Set audit level
sysctl security.mac.vlabel.audit_level=1

# View statistics
sysctl security.mac.vlabel.checks
sysctl security.mac.vlabel.denied
```

### kldload / kldunload

Module management:

```sh
# Load module
kldload mac_vlabel

# Or from file
kldload /path/to/mac_vlabel.ko

# Check if loaded
kldstat | grep vlabel

# Unload (if MPC_LOADTIME_FLAG_UNLOADOK)
kldunload mac_vlabel
```

### Loader Configuration

Auto-load at boot via `/boot/loader.conf`:

```sh
mac_vlabel_load="YES"
```

Or load the module file:
```sh
mac_vlabel_load="YES"
mac_vlabel_name="/boot/modules/mac_vlabel.ko"
```
