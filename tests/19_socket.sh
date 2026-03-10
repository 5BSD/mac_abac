#!/bin/sh
#
# Test: Socket Operations (connect/bind/listen/accept/send/receive)
#
# Tests that socket hooks enforce access control rules.
#
# Socket labels are inherited from the creating process credential.
# Rules can control:
#   - connect: outbound connections
#   - bind: binding to addresses/ports
#   - listen: listening for connections
#   - accept: accepting connections
#   - send: sending data
#   - receive: receiving data
#

set -e

SCRIPT_DIR=$(dirname "$0")
. "$SCRIPT_DIR/lib/test_helpers.sh"

# Configuration
if [ -n "$1" ]; then
	VLABELCTL="$1"
elif [ -x "$SCRIPT_DIR/../tools/vlabelctl" ]; then
	VLABELCTL="$SCRIPT_DIR/../tools/vlabelctl"
else
	VLABELCTL="./tools/vlabelctl"
fi
MODULE_NAME="mac_vlabel"
TEST_DIR="/root/vlabel_socket_$$"

# Check prerequisites
require_root

if ! kldstat -q -m "$MODULE_NAME" 2>/dev/null; then
	echo "Module not loaded. Please load the module first."
	exit 1
fi

# Cleanup function
cleanup() {
	"$VLABELCTL" mode permissive >/dev/null 2>&1 || true
	"$VLABELCTL" rule clear >/dev/null 2>&1 || true
	"$VLABELCTL" default allow >/dev/null 2>&1 || true
	rm -rf "$TEST_DIR" 2>/dev/null || true
	# Kill any test servers
	pkill -f "nc.*12345" 2>/dev/null || true
}
trap cleanup EXIT

echo "============================================"
echo "Socket Operations Tests"
echo "(connect/bind/listen/accept/send/receive)"
echo "============================================"
echo ""
info "Using vlabelctl: $VLABELCTL"
info "Test directory: $TEST_DIR"
echo ""

# ===========================================
# Setup
# ===========================================
info "=== Setup ==="

mkdir -p "$TEST_DIR"

# Test that socket operations are recognized
run_test
info "Test: Socket operations recognized in rules"
"$VLABELCTL" rule clear >/dev/null
if "$VLABELCTL" rule add "deny connect type=restricted -> *" >/dev/null 2>&1; then
	pass "connect operation accepted"
else
	fail "connect operation should be accepted"
fi

run_test
info "Test: bind operation"
if "$VLABELCTL" rule add "deny bind type=restricted -> *" >/dev/null 2>&1; then
	pass "bind operation accepted"
else
	fail "bind operation should be accepted"
fi

run_test
info "Test: listen operation"
if "$VLABELCTL" rule add "deny listen type=restricted -> *" >/dev/null 2>&1; then
	pass "listen operation accepted"
else
	fail "listen operation should be accepted"
fi

run_test
info "Test: accept operation"
if "$VLABELCTL" rule add "deny accept type=restricted -> *" >/dev/null 2>&1; then
	pass "accept operation accepted"
else
	fail "accept operation should be accepted"
fi

run_test
info "Test: send operation"
if "$VLABELCTL" rule add "deny send type=restricted -> *" >/dev/null 2>&1; then
	pass "send operation accepted"
else
	fail "send operation should be accepted"
fi

run_test
info "Test: receive operation"
if "$VLABELCTL" rule add "deny receive type=restricted -> *" >/dev/null 2>&1; then
	pass "receive operation accepted"
else
	fail "receive operation should be accepted"
fi

# ===========================================
# Test socket operations via vlabelctl test
# ===========================================
echo ""
info "=== Test Command Verification ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny connect type=untrusted -> *" >/dev/null
"$VLABELCTL" rule add "allow connect * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: connect denied for untrusted"
OUTPUT=$("$VLABELCTL" test connect "type=untrusted" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "connect denied for untrusted"
else
	fail "connect should be denied for untrusted (got: $OUTPUT)"
fi

run_test
info "Test: connect allowed for trusted"
OUTPUT=$("$VLABELCTL" test connect "type=trusted" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "connect allowed for trusted"
else
	fail "connect should be allowed for trusted (got: $OUTPUT)"
fi

# ===========================================
# Test bind restrictions
# ===========================================
echo ""
info "=== Bind Restrictions ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny bind type=user -> *" >/dev/null
"$VLABELCTL" rule add "allow bind type=webserver -> *" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: bind denied for user type"
OUTPUT=$("$VLABELCTL" test bind "type=user" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "bind denied for user type"
else
	fail "bind should be denied for user type (got: $OUTPUT)"
fi

run_test
info "Test: bind allowed for webserver type"
OUTPUT=$("$VLABELCTL" test bind "type=webserver" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "bind allowed for webserver type"
else
	fail "bind should be allowed for webserver type (got: $OUTPUT)"
fi

# ===========================================
# Test listen restrictions
# ===========================================
echo ""
info "=== Listen Restrictions ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "allow listen type=daemon -> *" >/dev/null
"$VLABELCTL" default deny >/dev/null

run_test
info "Test: listen allowed for daemon type"
OUTPUT=$("$VLABELCTL" test listen "type=daemon" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "listen allowed for daemon type"
else
	fail "listen should be allowed for daemon type (got: $OUTPUT)"
fi

run_test
info "Test: listen denied for other types (default deny)"
OUTPUT=$("$VLABELCTL" test listen "type=user" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "listen denied for user type"
else
	fail "listen should be denied for user type (got: $OUTPUT)"
fi

# ===========================================
# Test combined socket rules
# ===========================================
echo ""
info "=== Combined Socket Rules ==="

"$VLABELCTL" rule clear >/dev/null
# Network-isolated process: no connect, no listen
"$VLABELCTL" rule add "deny connect,bind,listen type=isolated -> *" >/dev/null
# Allow all other socket ops
"$VLABELCTL" rule add "allow connect,bind,listen,accept,send,receive * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: isolated process cannot connect"
OUTPUT=$("$VLABELCTL" test connect "type=isolated" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot connect"
else
	fail "isolated should not be able to connect (got: $OUTPUT)"
fi

run_test
info "Test: isolated process cannot bind"
OUTPUT=$("$VLABELCTL" test bind "type=isolated" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot bind"
else
	fail "isolated should not be able to bind (got: $OUTPUT)"
fi

run_test
info "Test: isolated process cannot listen"
OUTPUT=$("$VLABELCTL" test listen "type=isolated" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "isolated cannot listen"
else
	fail "isolated should not be able to listen (got: $OUTPUT)"
fi

run_test
info "Test: normal process can connect"
OUTPUT=$("$VLABELCTL" test connect "type=normal" "type=any" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "normal can connect"
else
	fail "normal should be able to connect (got: $OUTPUT)"
fi

# ===========================================
# Test deliver operation (packet delivery to socket)
# ===========================================
echo ""
info "=== Deliver Operation (Packet Delivery) ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny deliver type=external -> type=internal" >/dev/null
"$VLABELCTL" rule add "allow deliver * -> *" >/dev/null
"$VLABELCTL" default allow >/dev/null

run_test
info "Test: deliver operation recognized in rules"
if "$VLABELCTL" rule add "deny deliver type=untrusted -> *" >/dev/null 2>&1; then
	pass "deliver operation accepted"
else
	fail "deliver operation should be accepted"
fi

run_test
info "Test: deliver denied for external->internal"
OUTPUT=$("$VLABELCTL" test deliver "type=external" "type=internal" 2>&1 || true)
if echo "$OUTPUT" | grep -q "DENY"; then
	pass "deliver denied for external->internal"
else
	fail "deliver should be denied for external->internal (got: $OUTPUT)"
fi

run_test
info "Test: deliver allowed for trusted sources"
OUTPUT=$("$VLABELCTL" test deliver "type=trusted" "type=internal" 2>&1 || true)
if echo "$OUTPUT" | grep -q "ALLOW"; then
	pass "deliver allowed for trusted->internal"
else
	fail "deliver should be allowed for trusted->internal (got: $OUTPUT)"
fi

# ===========================================
# Test rule listing shows socket ops
# ===========================================
echo ""
info "=== Rule Display ==="

"$VLABELCTL" rule clear >/dev/null
"$VLABELCTL" rule add "deny connect,bind,listen,send,receive,deliver type=sandbox -> *" >/dev/null

run_test
info "Test: Rule list shows socket operations"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "connect" && echo "$OUTPUT" | grep -q "bind"; then
	pass "socket operations displayed in rule list"
else
	fail "socket operations should be in rule list (got: $OUTPUT)"
fi

run_test
info "Test: Rule list shows deliver operation"
OUTPUT=$("$VLABELCTL" rule list 2>&1)
if echo "$OUTPUT" | grep -q "deliver"; then
	pass "deliver operation displayed in rule list"
else
	fail "deliver operation should be in rule list (got: $OUTPUT)"
fi

# ===========================================
# Restore
# ===========================================
echo ""
info "=== Restore Safe State ==="
"$VLABELCTL" mode permissive
"$VLABELCTL" rule clear
"$VLABELCTL" default allow
info "Restored to permissive mode with no rules"

# ===========================================
# Summary
# ===========================================

summary
