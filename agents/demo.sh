#!/usr/bin/env sh
# demo.sh — stand up the agents-as-targets walkthrough on this machine:
#
#   1. build delegent, demo-agent and demo-call from this checkout
#   2. init a SEPARATE delegent home for the demo (default ~/.delegent-a2a-demo)
#   3. start the four demo agents (librarian, mailer, researcher, assistant)
#   4. register each one as an A2A target, minting the caller roles their own agent keys
#   5. mint a key for you (the harness) and start `delegent serve`
#
# Then point Claude Code at the printed URL, or use demo-call from the shell. Re-running is
# idempotent: existing targets and keys are kept. `demo.sh stop` stops what it started.
#
#   DEMO_HOME    where the demo's delegent state lives   (default ~/.delegent-a2a-demo)
#   DEMO_PORT    delegent's HTTP port                    (default 8091 — 8090 is usually your real delegent)
#   DEMO_BRAIN   scripted | ollama                       (default scripted)
#   DEMO_MODEL   the Ollama model for DEMO_BRAIN=ollama  (default llama3.2:3b)
#   DEMO_DEPTH   DELEGENT_MAX_DEPTH for serve            (default 3: harness→assistant→researcher→leaf)
#   DEMO_PACE    how long each agent step takes           (default 2s; 0 for instant)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
DEMO_HOME=${DEMO_HOME:-$HOME/.delegent-a2a-demo}
DEMO_PORT=${DEMO_PORT:-8091}
DEMO_BRAIN=${DEMO_BRAIN:-scripted}
DEMO_MODEL=${DEMO_MODEL:-llama3.2:3b}
DEMO_DEPTH=${DEMO_DEPTH:-3}
AGENT_PORT_BASE=${AGENT_PORT_BASE:-7100}
bin="$DEMO_HOME/bin"
keys="$DEMO_HOME/keys"
logs="$DEMO_HOME/logs"
delegent="$bin/delegent"

stop() {
  for f in "$DEMO_HOME"/*.pid; do
    [ -f "$f" ] || continue
    pid=$(cat "$f")
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" && echo "stopped $(basename "$f" .pid) ($pid)"; fi
    rm -f "$f"
  done
}

if [ "${1:-}" = "stop" ]; then stop; exit 0; fi

mkdir -p "$bin" "$keys" "$logs"
echo "== building"
(cd "$root/gateway" && go build -o "$delegent" ./cmd/delegent)
(cd "$root/agents" && go build -o "$bin/demo-agent" ./cmd/demo-agent && go build -o "$bin/demo-call" ./cmd/demo-call && go build -o "$bin/web-mcp" ./cmd/web-mcp)

if [ ! -f "$DEMO_HOME/config.json" ]; then
  echo "== init $DEMO_HOME"
  "$delegent" init --home "$DEMO_HOME" --listen "127.0.0.1:$DEMO_PORT"
fi

stop >/dev/null 2>&1 || true

echo "== starting the web MCP server"
"$bin/web-mcp" --port $((AGENT_PORT_BASE + 5)) --secret secret-web >"$logs/web-mcp.log" 2>&1 &
echo $! >"$DEMO_HOME/web-mcp.pid"

echo "== starting agents ($DEMO_BRAIN)"
DEMO_BRAIN="$DEMO_BRAIN" DEMO_MODEL="$DEMO_MODEL" DEMO_PACE="${DEMO_PACE:-2s}" DELEGENT_URL="http://127.0.0.1:$DEMO_PORT/mcp" \
  "$bin/demo-agent" --all --key-dir "$keys" --port-base "$AGENT_PORT_BASE" >"$logs/agents.log" 2>&1 &
echo $! >"$DEMO_HOME/agents.pid"
i=0
until curl -fs "http://127.0.0.1:$((AGENT_PORT_BASE + 4))/.well-known/agent-card.json" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 50 ] || { echo "agents did not come up; see $logs/agents.log"; exit 1; }
  sleep 0.2
done

echo "== registering the web server and the agents as targets"
existing=$("$delegent" target list --home "$DEMO_HOME" 2>/dev/null || true)
if printf '%s' "$existing" | grep -q "^web "; then
  echo "   web: already registered"
else
  "$delegent" target add --home "$DEMO_HOME" --id web --endpoint "http://127.0.0.1:$((AGENT_PORT_BASE + 5))/mcp" --credential secret-web | sed 's/^/   /'
fi
n=0
for role in librarian mailer researcher assistant; do
  n=$((n + 1))
  port=$((AGENT_PORT_BASE + n))
  if printf '%s' "$existing" | grep -q "^$role "; then
    echo "   $role: already registered"
    continue
  fi
  case $role in researcher|assistant) mint="--mint-key" ;; *) mint="" ;; esac
  out=$("$delegent" target add --home "$DEMO_HOME" --kind a2a --id "$role" --endpoint "http://127.0.0.1:$port" \
    --credential "secret-$role" $mint)
  printf '%s\n' "$out" | sed 's/^/   /'
  if [ -n "$mint" ]; then
    printf '%s\n' "$out" | grep -o 'dgk_[A-Za-z0-9_-]*' | head -1 >"$keys/$role.key"
    chmod 600 "$keys/$role.key"
  fi
done

if [ ! -s "$keys/harness.key" ]; then
  echo "== minting your (harness) key"
  "$delegent" key mint --home "$DEMO_HOME" --name claude-code | grep -o 'dgk_[A-Za-z0-9_-]*' | head -1 >"$keys/harness.key"
  chmod 600 "$keys/harness.key"
fi
harness=$(cat "$keys/harness.key")

if curl -fs -o /dev/null "http://127.0.0.1:$DEMO_PORT/" 2>/dev/null; then
  echo "port $DEMO_PORT is already in use (another delegent?) — pick one with DEMO_PORT=<port> $0"
  stop >/dev/null 2>&1 || true
  exit 1
fi
echo "== starting delegent serve on 127.0.0.1:$DEMO_PORT (DELEGENT_MAX_DEPTH=$DEMO_DEPTH)"
DELEGENT_MAX_DEPTH="$DEMO_DEPTH" "$delegent" serve --home "$DEMO_HOME" --addr "127.0.0.1:$DEMO_PORT" >"$logs/serve.log" 2>&1 &
serve_pid=$!
echo $serve_pid >"$DEMO_HOME/serve.pid"
i=0
until curl -fs -o /dev/null "http://127.0.0.1:$DEMO_PORT/" 2>/dev/null; do
  kill -0 $serve_pid 2>/dev/null || { echo "serve exited:"; tail -3 "$logs/serve.log"; exit 1; }
  i=$((i + 1)); [ $i -lt 50 ] || { echo "serve did not come up; see $logs/serve.log"; exit 1; }
  sleep 0.2
done

cat <<EOF

Demo is up.

  dashboard      http://127.0.0.1:$DEMO_PORT/           (approve agent asks in Alerts; see the Audit tab)
  approvals CLI  $delegent approvals --home $DEMO_HOME   (list) …approve <id>  …deny <id>
  logs           $logs/serve.log  $logs/agents.log

Connect Claude Code (HTTP transport, so serve and the agents share one process):

  claude mcp add --transport http delegent-demo http://127.0.0.1:$DEMO_PORT/mcp \\
    --header "Authorization: Bearer $harness"

Then ask Claude: "use researcher__research_topic to research solar panels and email the
summary to bob@acme.example". Or from the shell:

  $bin/demo-call --key-file $keys/harness.key --list
  $bin/demo-call --key-file $keys/harness.key researcher__research_topic \\
    '{"message":"research solar panels and email the summary to bob@acme.example"}'

Stop everything:  $0 stop
EOF
