#!/bin/sh
#
# Test: Policy Format Parsing
#
# Tests the different policy file formats supported by ABAC:
# 1. Line format (.rules) - mac_abac_ctl rule load/add
# 2. UCL format (.ucl) - mac_abac_ctl rule load (auto-detected by extension)
# 3. JSON format (.json) - mac_abac_ctl rule load (UCL is JSON superset)
#
# Prerequisites:
# - Must be run as root
# - Module must be loaded
# - mac_abac_ctl must be built
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
if [ -n "$1" ]; then
	MAC_ABAC_CTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/mac_abac_ctl" ]; then
	MAC_ABAC_CTL="$SCRIPT_DIR/../tools/mac_abac_ctl"
else
	MAC_ABAC_CTL="./tools/mac_abac_ctl"
fi

MODULE_NAME="mac_abac"
FIXTURES="$SCRIPT_DIR/fixtures/policies"

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	"$MAC_ABAC_CTL" mode permissive >/dev/null 2>&1 || true
	"$MAC_ABAC_CTL" rule clear >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "============================================"
echo "Policy Format Tests"
echo "============================================"
echo ""
info "Using mac_abac_ctl: $MAC_ABAC_CTL"
info "Using fixtures: $FIXTURES"
echo ""

# ===========================================
# Line Format Tests (.rules)
# ===========================================
info "=== Line Format (.rules) Tests ==="

run_test
info "Test: Basic allow/deny rules"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/minimal.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	pass "minimal.rules loaded"
else
	fail "minimal.rules (got: $OUTPUT)"
fi

run_test
info "Test: Multi-operation rules"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow read,write,mmap type=app -> type=data" >/dev/null 2>&1; then
	pass "multi-operation rule"
else
	fail "multi-operation rule"
fi

run_test
info "Test: Wildcard patterns"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * -> *" >/dev/null 2>&1; then
	pass "wildcard patterns"
else
	fail "wildcard patterns"
fi

run_test
info "Test: Negation pattern (!type=bad)"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "deny exec * -> !type=trusted" >/dev/null 2>&1; then
	pass "negation pattern"
else
	fail "negation pattern"
fi

run_test
info "Test: Multi-key patterns (type=a,domain=b)"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow read type=app,domain=web -> type=data,domain=web" >/dev/null 2>&1; then
	pass "multi-key patterns"
else
	fail "multi-key patterns"
fi

run_test
info "Test: Transition rule with newlabel"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "transition exec * -> type=setuid => type=elevated" >/dev/null 2>&1; then
	pass "transition with newlabel"
else
	fail "transition with newlabel"
fi

run_test
info "Test: Subject context constraint (ctx:)"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * -> type=admin ctx:uid=0" >/dev/null 2>&1; then
	pass "subject context (ctx:)"
else
	fail "subject context (ctx:)"
fi

run_test
info "Test: Subject context with uid"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * ctx:uid=0 -> type=admin" >/dev/null 2>&1; then
	pass "subject context before arrow"
else
	fail "subject context before arrow"
fi

run_test
info "Test: Object context constraint"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "deny debug * -> * ctx:sandboxed=true" >/dev/null 2>&1; then
	pass "object context (ctx:)"
else
	fail "object context (ctx:)"
fi

run_test
info "Test: Both subject and object context"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "deny signal * ctx:jail=any -> * ctx:jail=host" >/dev/null 2>&1; then
	pass "both contexts"
else
	fail "both contexts"
fi

run_test
info "Test: Context jail=host"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * -> * ctx:jail=host" >/dev/null 2>&1; then
	pass "context jail=host"
else
	fail "context jail=host"
fi

run_test
info "Test: Context jail=any"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "deny exec * -> type=hostonly ctx:jail=any" >/dev/null 2>&1; then
	pass "context jail=any"
else
	fail "context jail=any"
fi

run_test
info "Test: Context sandboxed=true"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "deny exec * -> * ctx:sandboxed=true" >/dev/null 2>&1; then
	pass "context sandboxed"
else
	fail "context sandboxed"
fi

run_test
info "Test: Context tty=true"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * -> type=interactive ctx:tty=true" >/dev/null 2>&1; then
	pass "context tty"
else
	fail "context tty"
fi

run_test
info "Test: Process operations (debug, signal, sched)"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow debug,signal,sched type=admin -> *" >/dev/null 2>&1; then
	pass "process operations"
else
	fail "process operations"
fi

run_test
info "Test: Complete rules file"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/valid_complete.rules" 2>&1)
if echo "$OUTPUT" | grep -q "loaded"; then
	COUNT=$(echo "$OUTPUT" | grep -o 'loaded [0-9]*' | grep -o '[0-9]*')
	if [ "$COUNT" -ge 5 ]; then
		pass "valid_complete.rules ($COUNT rules)"
	else
		fail "valid_complete.rules (only $COUNT rules)"
	fi
else
	fail "valid_complete.rules (got: $OUTPUT)"
fi

run_test
info "Test: Invalid syntax rejected"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "invalid syntax here" 2>/dev/null; then
	fail "invalid syntax should be rejected"
else
	pass "invalid syntax rejected"
fi

run_test
info "Test: Invalid action rejected"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "maybe exec * -> *" 2>/dev/null; then
	fail "invalid action should be rejected"
else
	pass "invalid action rejected"
fi

run_test
info "Test: Missing arrow rejected"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * *" 2>/dev/null; then
	fail "missing arrow should be rejected"
else
	pass "missing arrow rejected"
fi

# ===========================================
# UCL Format Tests (.ucl)
# ===========================================
echo ""
info "=== UCL Format (.ucl) Tests ==="

# mac_abac_ctl now supports UCL format directly via 'rule load'
run_test
info "Test: Basic UCL file parsing"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/ucl/basic.ucl" 2>&1)
if echo "$OUTPUT" | grep -q "loaded.*rules"; then
	pass "basic.ucl loaded"
else
	fail "basic.ucl (got: $OUTPUT)"
fi

run_test
info "Test: Complete UCL with all features"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/ucl/complete.ucl" 2>&1)
if echo "$OUTPUT" | grep -q "loaded.*rules"; then
	pass "complete.ucl loaded"
else
	fail "complete.ucl (got: $OUTPUT)"
fi

run_test
info "Test: Invalid UCL reports errors"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule load "$FIXTURES/ucl/invalid.ucl" >/dev/null 2>&1; then
	fail "invalid.ucl should report errors"
else
	pass "invalid.ucl reports errors"
fi

# ===========================================
# JSON Format Tests (.json)
# ===========================================
echo ""
info "=== JSON Format (.json) Tests ==="

# mac_abac_ctl supports JSON format (UCL is a superset of JSON)
run_test
info "Test: Basic JSON file parsing"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/json/basic.json" 2>&1)
if echo "$OUTPUT" | grep -q "loaded.*rules"; then
	pass "basic.json loaded"
else
	fail "basic.json (got: $OUTPUT)"
fi

run_test
info "Test: Complete JSON with all features"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$FIXTURES/json/complete.json" 2>&1)
if echo "$OUTPUT" | grep -q "loaded.*rules"; then
	pass "complete.json loaded"
else
	fail "complete.json (got: $OUTPUT)"
fi

run_test
info "Test: Invalid JSON reports errors"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule load "$FIXTURES/json/invalid.json" >/dev/null 2>&1; then
	fail "invalid.json should report errors"
else
	pass "invalid.json reports errors"
fi

run_test
info "Test: Malformed JSON rejected"
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule load "$FIXTURES/json/malformed.json" >/dev/null 2>&1; then
	fail "malformed.json should be rejected"
else
	pass "malformed.json rejected"
fi

# ===========================================
# Edge Cases
# ===========================================
echo ""
info "=== Edge Cases ==="

run_test
info "Test: Empty rule file"
TMPFILE=$(mktemp)
echo "" > "$TMPFILE"
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$TMPFILE" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 0 rules"; then
	pass "empty file loads 0 rules"
else
	# Some implementations may succeed silently
	if [ $? -eq 0 ]; then
		pass "empty file handled"
	else
		fail "empty file (got: $OUTPUT)"
	fi
fi
rm -f "$TMPFILE"

run_test
info "Test: Comments-only file"
TMPFILE=$(mktemp)
cat > "$TMPFILE" << 'EOF'
# This file contains only comments
# No actual rules here
# Should load 0 rules
EOF
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$TMPFILE" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 0 rules"; then
	pass "comments-only file"
else
	if [ $? -eq 0 ]; then
		pass "comments-only file handled"
	else
		fail "comments-only file (got: $OUTPUT)"
	fi
fi
rm -f "$TMPFILE"

run_test
info "Test: Mixed valid and comment lines"
TMPFILE=$(mktemp)
cat > "$TMPFILE" << 'EOF'
# First comment
allow exec * -> *
# Middle comment
deny exec * -> type=bad
# Final comment
EOF
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$TMPFILE" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 2 rules"; then
	pass "mixed valid and comments"
else
	fail "mixed valid and comments (got: $OUTPUT)"
fi
rm -f "$TMPFILE"

run_test
info "Test: Whitespace handling"
TMPFILE=$(mktemp)
cat > "$TMPFILE" << 'EOF'
   allow   exec   *   ->   *
	deny	exec	*	->	type=bad
EOF
"$MAC_ABAC_CTL" rule clear >/dev/null
OUTPUT=$("$MAC_ABAC_CTL" rule load "$TMPFILE" 2>&1)
if echo "$OUTPUT" | grep -q "loaded 2 rules"; then
	pass "whitespace handling"
else
	fail "whitespace handling (got: $OUTPUT)"
fi
rm -f "$TMPFILE"

run_test
info "Test: Long pattern values (63-char limit for rules)"
# Rule pattern values are limited to 63 chars (ABAC_RULE_VALUE_LEN - 1)
LONG_VALUE=$(printf 'x%.0s' $(seq 1 63))
"$MAC_ABAC_CTL" rule clear >/dev/null
if "$MAC_ABAC_CTL" rule add "allow exec * -> type=$LONG_VALUE" >/dev/null 2>&1; then
	pass "63-char pattern value accepted"
else
	fail "63-char pattern value"
fi

# ===========================================
# Summary
# ===========================================

summary
