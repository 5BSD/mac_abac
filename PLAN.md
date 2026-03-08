# vLabel Implementation Plan

## Part 1: Add `vlabelctl rule load` Command

### Overview
Add ability to load multiple rules from a file, complementing the existing single-rule `rule add` command.

### Changes Required

#### 1. vlabelctl.c - Add `rule load` subcommand

```c
// New function
static int
cmd_rule_load(const char *path)
{
    FILE *fp;
    char line[2048];
    int lineno = 0;
    int loaded = 0;
    int errors = 0;
    struct vlabel_rule_io rule;

    fp = fopen(path, "r");
    if (fp == NULL)
        err(EX_NOINPUT, "open %s", path);

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;

        // Strip comments and whitespace
        char *p = strchr(line, '#');
        if (p) *p = '\0';

        // Trim leading/trailing whitespace
        // Skip empty lines

        // Parse and add rule
        int ret = vlabeld_parse_line(line, &rule);
        if (ret < 0) {
            warnx("%s:%d: invalid rule syntax", path, lineno);
            errors++;
            continue;
        }
        if (ret > 0) // empty line
            continue;

        if (ioctl(dev_fd, VLABEL_IOC_RULE_ADD, &rule) < 0) {
            warn("%s:%d: ioctl(RULE_ADD)", path, lineno);
            errors++;
            continue;
        }

        loaded++;
    }

    fclose(fp);
    printf("loaded %d rules (%d errors)\n", loaded, errors);
    return (errors > 0 ? 1 : 0);
}
```

#### 2. Update usage text

```c
"  rule load <file>\n"
"      Load rules from a file (one rule per line)\n"
"      Lines starting with # are comments\n"
```

#### 3. File format

```
# /etc/vlabel/policy.rules
# Comments start with #

# Deny untrusted executables
deny exec * -> type=untrusted

# Allow web domain access
allow read,write domain=web -> domain=web

# Transitions
transition exec type=user -> name=nginx newlabel=type=daemon,domain=web

# Catch-all
allow exec * -> *
```

---

## Part 2: Comprehensive Test Suite Plan

### Current Test Coverage

| Test File | What It Tests |
|-----------|---------------|
| 01_load_unload.sh | Module load/unload, sysctl tree |
| 02_vlabelctl.sh | Mode, audit, default, stats, status, basic rules |
| 03_label_format.sh | Label set/get, format conversion, validation |
| 04_default_policy.sh | Default allow/deny behavior |
| 05_debug_check.sh | debug/signal/sched operations |

### Missing Coverage

| Feature | Currently Tested? |
|---------|-------------------|
| **Labels** | |
| File labeling (set/get/remove) | ✅ Basic |
| Label format conversion | ✅ |
| Label validation (limits) | ✅ |
| Kernel label caching | ❌ |
| Label inheritance on fork | ❌ |
| **Rules** | |
| Rule add/remove/list/clear | ✅ Basic |
| Rule load from file | ❌ (not implemented yet) |
| Pattern matching wildcards | ❌ |
| Pattern matching negation | ❌ |
| Multi-operation rules | ✅ Basic |
| Context constraints | ❌ |
| **Transitions** | |
| Transition rule parsing | ✅ Basic |
| Transition on exec | ❌ |
| Transition newlabel | ❌ |
| Conditional transitions | ❌ |
| **Enforcement** | |
| exec enforcement | ❌ |
| debug/signal/sched enforcement | ❌ |
| Permissive vs enforcing mode | ❌ |
| Default policy behavior | ✅ (via test command) |
| **Audit** | |
| Audit event generation | ❌ |
| Monitor command | ❌ |
| **Integration** | |
| Real exec blocked by policy | ❌ |
| Real transition on exec | ❌ |
| Multi-process scenarios | ❌ |
| Jail context constraints | ❌ |

---

### New Test Suite Structure

```
tests/
├── run_all.sh                    # Master test runner
├── lib/
│   └── test_helpers.sh           # Shared functions
│
├── 01_module/
│   └── 01_load_unload.sh         # Module lifecycle
│
├── 02_vlabelctl/
│   ├── 01_mode.sh                # Mode get/set
│   ├── 02_audit.sh               # Audit levels
│   ├── 03_default_policy.sh      # Default policy
│   ├── 04_stats.sh               # Statistics
│   └── 05_status.sh              # Combined status
│
├── 03_labels/
│   ├── 01_basic.sh               # Set/get/remove
│   ├── 02_format.sh              # Format conversion
│   ├── 03_validation.sh          # Limit enforcement
│   └── 04_kernel_cache.sh        # Kernel caching
│
├── 04_rules/
│   ├── 01_add_remove.sh          # Basic rule management
│   ├── 02_load_file.sh           # Load from file (new)
│   ├── 03_patterns.sh            # Pattern matching
│   ├── 04_negation.sh            # Negation patterns
│   ├── 05_operations.sh          # Operation bitmasks
│   └── 06_context.sh             # Context constraints
│
├── 05_transitions/
│   ├── 01_parsing.sh             # Transition rule parsing
│   ├── 02_newlabel.sh            # newlabel field
│   └── 03_conditional.sh         # Context-based transitions
│
├── 06_enforcement/
│   ├── 01_exec_allow.sh          # Exec allowed by rule
│   ├── 02_exec_deny.sh           # Exec blocked by rule
│   ├── 03_permissive.sh          # Permissive mode logging
│   ├── 04_enforcing.sh           # Enforcing mode blocking
│   ├── 05_debug.sh               # ptrace/debug checks
│   ├── 06_signal.sh              # Signal checks
│   └── 07_sched.sh               # Scheduler checks
│
├── 07_transitions_real/
│   ├── 01_basic.sh               # Simple transition on exec
│   ├── 02_chain.sh               # Chained transitions
│   └── 03_context.sh             # Context-dependent
│
├── 08_audit/
│   ├── 01_events.sh              # Event generation
│   └── 02_monitor.sh             # Monitor command
│
├── 09_integration/
│   ├── 01_web_sandbox.sh         # Web server isolation
│   ├── 02_privilege_drop.sh      # Privilege dropping
│   └── 03_jail_context.sh        # Jail constraints
│
└── fixtures/
    ├── policies/
    │   ├── minimal.rules
    │   ├── web_sandbox.rules
    │   └── multi_tenant.rules
    └── binaries/
        └── (test helper programs)
```

---

### Detailed Test Specifications

#### 03_labels/01_basic.sh

```sh
# Test: Basic label operations
# - Set label on file
# - Get label from file
# - Remove label from file
# - Get label from unlabeled file (should show "(no label)")
# - Set label on directory
# - Set label on symlink
```

#### 04_rules/03_patterns.sh

```sh
# Test: Pattern matching

# Wildcard patterns
vlabelctl rule add "allow exec * -> *"
# Should match any subject, any object

# Single key match
vlabelctl rule add "deny exec * -> type=untrusted"
# Should match any subject, objects with type=untrusted

# Multi-key match (AND)
vlabelctl rule add "deny exec * -> type=app,domain=restricted"
# Should only match if BOTH type=app AND domain=restricted

# Verify via test command
vlabelctl test exec "type=user" "type=untrusted"  # DENY
vlabelctl test exec "type=user" "type=trusted"    # ALLOW
vlabelctl test exec "type=user" "type=app,domain=restricted"  # DENY
vlabelctl test exec "type=user" "type=app,domain=web"         # ALLOW
```

#### 04_rules/04_negation.sh

```sh
# Test: Negation patterns

# Negated object pattern
vlabelctl rule add "allow exec * -> !type=untrusted"
vlabelctl test exec "type=user" "type=trusted"    # ALLOW
vlabelctl test exec "type=user" "type=untrusted"  # DENY (falls through)

# Negated subject pattern
vlabelctl rule add "deny exec !type=admin -> type=system"
vlabelctl test exec "type=user" "type=system"     # DENY
vlabelctl test exec "type=admin" "type=system"    # ALLOW
```

#### 04_rules/06_context.sh

```sh
# Test: Context constraints

# UID constraint
vlabelctl rule add "allow exec * -> type=admin context:uid=0"
vlabelctl test exec "type=user" "type=admin"  # Result depends on test UID

# Jail constraint
vlabelctl rule add "deny exec * -> type=hostonly context:jail=any"
# In jail: DENY
# On host: ALLOW (rule doesn't match)

# TTY constraint
vlabelctl rule add "allow exec * -> type=interactive context:tty=true"

# Sandbox constraint
vlabelctl rule add "deny exec * -> * context:sandboxed=true"
```

#### 06_enforcement/02_exec_deny.sh

```sh
# Test: Exec actually blocked in enforcing mode

# Setup
vlabelctl mode enforcing
vlabelctl default deny
vlabelctl rule add "deny exec * -> type=blocked"

# Create test binary and label it
cp /bin/echo /tmp/test_blocked
vlabelctl label set /tmp/test_blocked "type=blocked"

# Try to execute - should fail with EACCES
if /tmp/test_blocked "should not run" 2>/dev/null; then
    fail "Exec should have been blocked"
else
    pass "Exec blocked by policy"
fi

# Cleanup
rm /tmp/test_blocked
vlabelctl rule clear
vlabelctl mode permissive
```

#### 07_transitions_real/01_basic.sh

```sh
# Test: Process label changes on exec

# Setup
vlabelctl mode enforcing
vlabelctl rule add "transition exec type=user -> type=app newlabel=type=daemon"
vlabelctl rule add "allow exec * -> *"

# Create test binary that prints its own label
cat > /tmp/print_label.c << 'EOF'
#include <sys/extattr.h>
#include <stdio.h>
int main() {
    // Read credential label via mac_get_proc()
    // Print it
    printf("my label: ...\n");
    return 0;
}
EOF
cc -o /tmp/print_label /tmp/print_label.c

# Label the binary
vlabelctl label set /tmp/print_label "type=app"

# Execute and check label changed
OUTPUT=$(/tmp/print_label)
if echo "$OUTPUT" | grep -q "type=daemon"; then
    pass "Transition applied"
else
    fail "Transition not applied (got: $OUTPUT)"
fi
```

---

### Test Helper Library (lib/test_helpers.sh)

```sh
#!/bin/sh
# Shared test functions

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    printf "${GREEN}PASS${NC}: %s\n" "$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    printf "${RED}FAIL${NC}: %s\n" "$1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

skip() {
    printf "${YELLOW}SKIP${NC}: %s\n" "$1"
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
}

assert_equals() {
    if [ "$1" = "$2" ]; then
        pass "$3"
    else
        fail "$3 (expected '$1', got '$2')"
    fi
}

assert_contains() {
    if echo "$1" | grep -q "$2"; then
        pass "$3"
    else
        fail "$3 (expected to contain '$2', got '$1')"
    fi
}

assert_exit_code() {
    eval "$1" >/dev/null 2>&1
    ACTUAL=$?
    if [ "$ACTUAL" -eq "$2" ]; then
        pass "$3"
    else
        fail "$3 (expected exit $2, got $ACTUAL)"
    fi
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This test requires root"
        exit 1
    fi
}

require_module() {
    if ! kldstat -q -m mac_vlabel 2>/dev/null; then
        echo "Module not loaded"
        exit 1
    fi
}

summary() {
    echo ""
    echo "============================================"
    echo "Tests run:    $TESTS_RUN"
    echo "Tests passed: $TESTS_PASSED"
    echo "Tests failed: $TESTS_FAILED"
    echo "============================================"

    if [ $TESTS_FAILED -eq 0 ]; then
        printf "${GREEN}ALL TESTS PASSED${NC}\n"
        return 0
    else
        printf "${RED}SOME TESTS FAILED${NC}\n"
        return 1
    fi
}
```

---

### Test Fixtures

#### fixtures/policies/minimal.rules
```
# Minimal test policy
allow exec * -> *
```

#### fixtures/policies/web_sandbox.rules
```
# Web server sandbox policy

# Web processes can only access web files
allow read,write domain=web -> domain=web
allow read,exec domain=web -> type=shared

# Web can't touch system files
deny read,write domain=web -> type=system

# Transition nginx to web domain
transition exec type=init -> name=nginx newlabel=type=daemon,domain=web

# Default deny
deny all * -> *
```

#### fixtures/policies/multi_tenant.rules
```
# Multi-tenant isolation

# Tenant A isolation
allow all tenant=acme -> tenant=acme
deny read,write,exec tenant=acme -> tenant=globex

# Tenant B isolation
allow all tenant=globex -> tenant=globex
deny read,write,exec tenant=globex -> tenant=acme

# Shared resources
allow read,exec * -> type=platform

# Default deny cross-tenant
deny all * -> *
```

---

## Part 3: Rule Validation Tool

### Overview
Add `vlabelctl rule validate` command to check rules without loading them into the kernel.

### Commands

```sh
# Validate a single rule
vlabelctl rule validate "deny exec * -> type=untrusted"
# Output: OK

vlabelctl rule validate "deny exec * -> type=untrsuted"
# Output: OK (syntactically valid, can't catch typos)

vlabelctl rule validate "invalid garbage here"
# Output: ERROR: invalid rule syntax

# Validate a file
vlabelctl rule validate -f /etc/vlabel/policy.rules
# Output:
#   Line 1: OK - deny exec * -> type=untrusted
#   Line 2: OK - allow read,write domain=web -> domain=web
#   Line 5: ERROR - missing '->' separator
#
#   Summary: 4 valid, 1 error
```

### Validation Checks

| Check | Description |
|-------|-------------|
| **Syntax** | action operation subject -> object [newlabel] [context] |
| **Action** | Must be allow, deny, or transition |
| **Operations** | Must be valid ops (exec, read, write, etc.) or 'all' |
| **Pattern format** | key=value,key=value or * or !pattern |
| **Key length** | Max 63 bytes |
| **Value length** | Max 255 bytes |
| **Pair count** | Max 32 pairs per pattern |
| **Transition** | If action=transition, newlabel should be present |
| **Context** | context:key=value format valid |

### Implementation

```c
// vlabelctl.c

static int
cmd_rule_validate(int argc, char *argv[])
{
    struct vlabel_rule_io rule;
    int ret;
    int from_file = 0;
    const char *input;

    // Parse arguments
    if (argc >= 2 && strcmp(argv[0], "-f") == 0) {
        from_file = 1;
        input = argv[1];
    } else if (argc >= 1) {
        input = argv[0];
    } else {
        errx(EX_USAGE, "rule validate requires a rule or -f <file>");
    }

    if (from_file) {
        return validate_rules_file(input);
    }

    // Validate single rule (doesn't need device open)
    ret = vlabeld_parse_line(input, &rule);
    if (ret < 0) {
        printf("ERROR: invalid rule syntax\n");
        return (1);
    }
    if (ret > 0) {
        printf("ERROR: empty rule\n");
        return (1);
    }

    // Additional semantic checks
    if (rule.vr_action == VLABEL_ACTION_TRANSITION) {
        if (rule.vr_newlabel[0] == '\0') {
            printf("WARNING: transition rule has no newlabel\n");
        }
    }

    printf("OK\n");
    return (0);
}

static int
validate_rules_file(const char *path)
{
    FILE *fp;
    char line[2048];
    int lineno = 0;
    int valid = 0;
    int errors = 0;
    int warnings = 0;
    struct vlabel_rule_io rule;

    fp = fopen(path, "r");
    if (fp == NULL)
        err(EX_NOINPUT, "open %s", path);

    while (fgets(line, sizeof(line), fp) != NULL) {
        lineno++;

        // Strip comments
        char *p = strchr(line, '#');
        if (p) *p = '\0';

        // Trim whitespace
        char *start = line;
        while (*start == ' ' || *start == '\t') start++;
        char *end = start + strlen(start) - 1;
        while (end > start && (*end == '\n' || *end == '\r' || *end == ' ')) {
            *end = '\0';
            end--;
        }

        // Skip empty lines
        if (*start == '\0')
            continue;

        int ret = vlabeld_parse_line(start, &rule);
        if (ret < 0) {
            printf("Line %d: ERROR - %s\n", lineno, start);
            errors++;
        } else if (ret > 0) {
            // Empty after parsing (shouldn't happen after trim)
            continue;
        } else {
            // Check for warnings
            if (rule.vr_action == VLABEL_ACTION_TRANSITION &&
                rule.vr_newlabel[0] == '\0') {
                printf("Line %d: WARNING - transition without newlabel: %s\n",
                    lineno, start);
                warnings++;
            }
            printf("Line %d: OK - %s\n", lineno, start);
            valid++;
        }
    }

    fclose(fp);

    printf("\nSummary: %d valid, %d errors, %d warnings\n",
        valid, errors, warnings);

    return (errors > 0 ? 1 : 0);
}
```

### Test Fixtures for Validation

#### fixtures/policies/valid_complete.rules
```
# Complete valid policy for validation testing

# Basic rules
allow exec * -> *
deny exec * -> type=untrusted
allow read,write domain=web -> domain=web

# Multi-operation
allow read,write,mmap,stat domain=app -> domain=app

# Negation
deny exec * -> !type=trusted
allow exec !type=restricted -> *

# Transitions
transition exec type=user -> name=nginx newlabel=type=daemon,domain=web
transition exec type=init -> type=app newlabel=type=daemon

# Context constraints
allow exec * -> type=admin context:uid=0
deny exec * -> type=hostonly context:jail=any
allow exec * -> type=interactive context:tty=true
deny exec * -> * context:sandboxed=true

# Complex patterns
allow read type=app,domain=web,tier=frontend -> type=data,domain=web,sensitivity=public
deny write type=app,env=prod -> type=config,critical=true

# Wildcards in values
allow read * -> domain=*
```

#### fixtures/policies/invalid_syntax.rules
```
# Invalid rules for testing error detection

# Missing arrow
deny exec * type=untrusted

# Invalid action
permit exec * -> *

# Invalid operation
deny foo * -> *

# Empty pattern where not allowed
deny exec -> type=untrusted

# Missing object
allow exec * ->

# Garbage
this is not a rule at all

# Bad context syntax
allow exec * -> * context:badformat

# Valid rule to ensure we continue parsing
allow exec * -> *
```

#### fixtures/policies/warnings.rules
```
# Rules that should generate warnings

# Transition without newlabel
transition exec * -> type=app

# Valid rules mixed in
allow exec * -> *
deny exec * -> type=blocked
```

### Validation Tests (04_rules/07_validate.sh)

```sh
#!/bin/sh
#
# Test: Rule validation

. ../lib/test_helpers.sh

VLABELCTL="${VLABELCTL:-../../tools/vlabelctl}"
FIXTURES="../../fixtures/policies"

require_root  # Optional - validate doesn't need kernel

echo "============================================"
echo "Rule Validation Tests"
echo "============================================"
echo ""

# ===========================================
# Single rule validation
# ===========================================
info "=== Single Rule Validation ==="

run_test
info "Test: Valid simple rule"
OUTPUT=$($VLABELCTL rule validate "allow exec * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "valid simple rule"
else
    fail "valid simple rule (got: $OUTPUT)"
fi

run_test
info "Test: Valid deny rule"
OUTPUT=$($VLABELCTL rule validate "deny exec * -> type=untrusted" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "valid deny rule"
else
    fail "valid deny rule"
fi

run_test
info "Test: Valid transition rule"
OUTPUT=$($VLABELCTL rule validate "transition exec * -> type=app newlabel=type=daemon" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "valid transition rule"
else
    fail "valid transition rule"
fi

run_test
info "Test: Valid rule with context"
OUTPUT=$($VLABELCTL rule validate "allow exec * -> type=admin context:uid=0" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "valid context rule"
else
    fail "valid context rule"
fi

run_test
info "Test: Invalid - missing arrow"
OUTPUT=$($VLABELCTL rule validate "deny exec * type=untrusted" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "missing arrow rejected"
else
    fail "missing arrow rejected"
fi

run_test
info "Test: Invalid - bad action"
OUTPUT=$($VLABELCTL rule validate "permit exec * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "bad action rejected"
else
    fail "bad action rejected"
fi

run_test
info "Test: Invalid - bad operation"
OUTPUT=$($VLABELCTL rule validate "deny foo * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "bad operation rejected"
else
    fail "bad operation rejected"
fi

run_test
info "Test: Invalid - garbage"
OUTPUT=$($VLABELCTL rule validate "this is not a rule" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "garbage rejected"
else
    fail "garbage rejected"
fi

# ===========================================
# File validation
# ===========================================
info ""
info "=== File Validation ==="

run_test
info "Test: Validate complete valid file"
OUTPUT=$($VLABELCTL rule validate -f "$FIXTURES/valid_complete.rules" 2>&1)
if echo "$OUTPUT" | grep -q "0 errors"; then
    pass "valid file passes"
else
    fail "valid file passes (got: $OUTPUT)"
fi

run_test
info "Test: Validate file with errors"
OUTPUT=$($VLABELCTL rule validate -f "$FIXTURES/invalid_syntax.rules" 2>&1)
if echo "$OUTPUT" | grep -q "errors" && ! echo "$OUTPUT" | grep -q "0 errors"; then
    pass "invalid file detected"
else
    fail "invalid file detected"
fi

run_test
info "Test: Validate file with warnings"
OUTPUT=$($VLABELCTL rule validate -f "$FIXTURES/warnings.rules" 2>&1)
if echo "$OUTPUT" | grep -q "WARNING"; then
    pass "warnings generated"
else
    fail "warnings generated"
fi

run_test
info "Test: Validate non-existent file"
OUTPUT=$($VLABELCTL rule validate -f "/nonexistent/file.rules" 2>&1)
if [ $? -ne 0 ]; then
    pass "non-existent file fails"
else
    fail "non-existent file fails"
fi

# ===========================================
# Edge cases
# ===========================================
info ""
info "=== Edge Cases ==="

run_test
info "Test: Empty rule"
OUTPUT=$($VLABELCTL rule validate "" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "empty rule rejected"
else
    fail "empty rule rejected"
fi

run_test
info "Test: Rule with maximum key length (63 bytes)"
KEY63=$(printf 'k%.0s' $(seq 1 63))
OUTPUT=$($VLABELCTL rule validate "allow exec ${KEY63}=value -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "max key length accepted"
else
    fail "max key length accepted"
fi

run_test
info "Test: Rule with key too long (64 bytes)"
KEY64=$(printf 'k%.0s' $(seq 1 64))
OUTPUT=$($VLABELCTL rule validate "allow exec ${KEY64}=value -> *" 2>&1)
if echo "$OUTPUT" | grep -q "ERROR"; then
    pass "key too long rejected"
else
    fail "key too long rejected"
fi

run_test
info "Test: All valid operations"
for op in exec read write mmap link rename unlink chdir stat readdir create open access lookup setextattr getextattr debug signal sched all; do
    OUTPUT=$($VLABELCTL rule validate "allow $op * -> *" 2>&1)
    if ! echo "$OUTPUT" | grep -q "OK"; then
        fail "operation '$op' should be valid"
    fi
done
pass "all operations valid"

run_test
info "Test: Multi-operation rule"
OUTPUT=$($VLABELCTL rule validate "allow exec,read,write,mmap * -> *" 2>&1)
if echo "$OUTPUT" | grep -q "OK"; then
    pass "multi-operation rule"
else
    fail "multi-operation rule"
fi

summary
```

---

### Implementation Priority

1. **Phase 1: Rule Load Feature**
   - Add `vlabelctl rule load` command
   - Add test for rule loading

2. **Phase 2: Test Infrastructure**
   - Create test helper library
   - Reorganize existing tests
   - Add fixtures directory

3. **Phase 3: Pattern Tests**
   - Pattern matching tests
   - Negation tests
   - Context constraint tests

4. **Phase 4: Enforcement Tests**
   - Real exec blocking tests
   - Mode behavior tests
   - Process operation tests

5. **Phase 5: Transition Tests**
   - Basic transition tests
   - Context-dependent transitions
   - Label inheritance tests

6. **Phase 6: Integration Tests**
   - Multi-process scenarios
   - Jail integration
   - Complete policy scenarios

---

## TODO: Documentation Needed

### VM Testing Documentation

Document how to run the test suite, clearly distinguishing what requires a VM vs what can run locally.

#### Tests that do NOT require VM (run locally):
- `06_rule_validate.sh` - Rule validation (uses parser only, no kernel)
- Building vlabelctl, vlabeld

#### Tests that REQUIRE VM (need kernel module loaded):
- `01_load_unload.sh` - Module load/unload
- `02_vlabelctl.sh` - Mode, audit, stats (needs /dev/vlabel)
- `03_label_format.sh` - Label operations (needs extattr + kernel)
- `04_default_policy.sh` - Default policy tests
- `05_debug_check.sh` - Debug/signal/sched operations
- `07_rule_load.sh` - Loading rules into kernel

#### Deployment workflow:
```sh
# 1. Build locally
make -C kernel SYSDIR=/usr/src/sys
make -C tools
make -C daemon

# 2. Deploy to VM
./scripts/deploy-test.sh

# 3. Run tests on VM
ssh root@VM_IP "cd /root && sh run_all.sh"
```

#### VM setup requirements:
- FreeBSD 15.0+
- Kernel sources at /usr/src/sys
- SSH access as root
- IP configured in deploy-test.sh (default: 192.168.7.134)

---

## TODO: Future Improvements

### Increase Label Size Limits

Current limits are constrained by kernel stack size and ioctl buffer limits:

| Limit | Current | Ideal |
|-------|---------|-------|
| Max key | 32 bytes | 64 bytes |
| Max value | 96 bytes | 256 bytes |
| Max pairs | 8 | 16-32 |
| Max label string | 1KB | 4KB |

To increase these limits, need to:
1. Allocate `struct vlabel_rule` with `malloc()` instead of stack in `vlabel_dev_ioctl()`
2. Use `copyin()` for large ioctl data instead of relying on kernel ioctl buffer
3. Consider using a different interface (sysctl, file-based) for bulk rule loading
