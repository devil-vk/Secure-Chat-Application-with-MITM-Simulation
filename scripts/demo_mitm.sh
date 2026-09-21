#!/usr/bin/env bash
#
# demo_mitm.sh — automated walkthrough of the security properties.
#
# Runs four non-interactive scenarios and prints what happened:
#   1. Baseline    : secure chat with certificate verification (works).
#   2. Defence     : verifying client vs MITM proxy (interception BLOCKED).
#   3. Attack      : insecure client vs MITM proxy (interception SUCCEEDS).
#   4. Downgrade   : TLS-1.3 floor defeats a downgrade; a 1.2 server is downgraded.
#
# Run from the project root after `make` and `make certs`:
#   ./scripts/demo_mitm.sh
set -uo pipefail
cd "$(dirname "$0")/.."

BIN=build/bin
[ -x "$BIN/chat_server" ] || { echo "build first: run 'make'"; exit 1; }
[ -f certs/server.crt ]  || { echo "generate certs first: run 'make certs'"; exit 1; }

hr() { printf '\n\033[1m%s\033[0m\n' "============================================================"; }
say() { printf '\033[1;36m%s\033[0m\n' "$*"; }

cleanup() { pkill -f "$BIN/chat_server"  2>/dev/null; pkill -f "$BIN/mitm_proxy" 2>/dev/null; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
hr; say "SCENARIO 1 — Baseline secure chat (cert verification ON)"
cleanup; sleep 0.3
"$BIN/chat_server" --port 8443 >/tmp/demo_srv.log 2>&1 &
sleep 1
( sleep 2.5; echo /quit ) | "$BIN/chat_client" --port 8443 --name alice >/tmp/demo_alice.log 2>&1 &
sleep 0.8
( echo "meet me at 5pm"; sleep 1; echo /quit ) | "$BIN/chat_client" --port 8443 --name bob >/tmp/demo_bob.log 2>&1
sleep 1
echo "server saw:"; grep -E "joined|\]" /tmp/demo_srv.log | sed 's/^/    /'
echo "alice received:"; grep -E "bob:" /tmp/demo_alice.log | sed 's/^/    /'
cleanup; sleep 0.5

# ---------------------------------------------------------------------------
hr; say "SCENARIO 2 — MITM vs a VERIFYING client (chain of trust defends)"
"$BIN/chat_server" --port 8443 >/tmp/demo_srv.log 2>&1 &
"$BIN/mitm_proxy" --listen-port 8444 --server-port 8443 >/tmp/demo_mitm.log 2>&1 &
sleep 1
( sleep 1; echo /quit ) | "$BIN/chat_client" --port 8444 --name victim >/tmp/demo_victim.log 2>&1
sleep 0.5
echo "client result:"; grep -E "verification result|refusing" /tmp/demo_victim.log | sed 's/^/    /'
echo "proxy result:";  grep -E "REJECTED|blocked" /tmp/demo_mitm.log | sed 's/^/    /'
cleanup; sleep 0.5

# ---------------------------------------------------------------------------
hr; say "SCENARIO 3 — MITM vs an INSECURE client (interception succeeds)"
"$BIN/chat_server" --port 8443 >/tmp/demo_srv.log 2>&1 &
"$BIN/mitm_proxy" --listen-port 8444 --server-port 8443 >/tmp/demo_mitm.log 2>&1 &
sleep 1
( echo "my password is hunter2"; sleep 1; echo /quit ) | \
    "$BIN/chat_client" --port 8444 --name victim --insecure >/tmp/demo_victim.log 2>&1
sleep 0.5
echo "proxy intercepted (cleartext!):"; grep -E "intercepted" /tmp/demo_mitm.log | sed 's/^/    /'
cleanup; sleep 0.5

# ---------------------------------------------------------------------------
hr; say "SCENARIO 4 — SSL downgrade: protocol floor defends"
echo "(a) server requires TLS 1.3, attacker strips it -> downgrade FAILS"
"$BIN/chat_server" --port 8443 --min-version 1.3 >/tmp/demo_srv.log 2>&1 &
"$BIN/mitm_proxy" --listen-port 8444 --server-port 8443 --downgrade >/tmp/demo_mitm.log 2>&1 &
sleep 1
( sleep 1; echo /quit ) | "$BIN/chat_client" --port 8444 --name victim --insecure >/tmp/demo_victim.log 2>&1
sleep 0.5
if grep -q "intercepted" /tmp/demo_mitm.log; then echo "    UNEXPECTED: interception happened"; \
  else echo "    downgrade blocked — no messages intercepted"; fi
cleanup; sleep 0.5

echo "(b) server still allows TLS 1.2, attacker strips 1.3 -> downgraded to 1.2"
"$BIN/chat_server" --port 8445 --min-version 1.2 >/tmp/demo_srv.log 2>&1 &
"$BIN/mitm_proxy" --listen-port 8446 --server-port 8445 --downgrade >/tmp/demo_mitm.log 2>&1 &
sleep 1
( echo "weak-tls secret"; sleep 1; echo /quit ) | \
    "$BIN/chat_client" --port 8446 --name victim --insecure >/tmp/demo_victim.log 2>&1
sleep 0.5
grep -E "upstream session|intercepted" /tmp/demo_mitm.log | sed 's/^/    /'

hr; say "Demo complete."
