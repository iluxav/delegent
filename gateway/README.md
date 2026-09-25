# delegent — the local Delegent gateway

A single-binary, single-operator MCP gateway: put it in front of the MCP servers your agents
use and every tool call passes through **entitlements, human consent, and tamper-evident
receipts** before it reaches a vendor. No database, no account — state is plain JSON files in
one directory, secrets sealed with a master key only you hold.

This is the same engine the hosted Delegent product runs. The protocol math it enforces —
capability slips, the authorization algebra, receipt hash chains — lives in the stdlib-only
[`delegent.dev/protocol`](../protocol) library, so anyone can verify what this gateway does.

## Install

```sh
curl -fsSL https://delegent.dev/install.sh | sh
```

Installs prebuilt `delegent` + `delegent-proto` binaries (macOS/Linux, amd64/arm64,
checksum-verified). Or build from source:

```sh
go install delegent.dev/gateway/cmd/delegent@latest
```

## Quickstart (stdio — Claude Code, Claude Desktop, Cursor, …)

```sh
delegent init
delegent target add --id github --endpoint https://your-mcp-server.example/mcp --credential <upstream token>
delegent key mint --name laptop        # prints the agent key ONCE
```

Then point your MCP client at the binary instead of at the vendors. Claude Code
(`.mcp.json`) / Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "delegent": {
      "command": "delegent",
      "args": ["stdio"],
      "env": { "DELEGENT_AGENT_KEY": "dgk_…" }
    }
  }
}
```

One entry fronts **all** your targets: tools arrive namespaced `<target>__<tool>`
(`github__create_issue`), and every call carries the agent's self-declared why
(`_delegent_intent`) into the consent prompt. Clients that support MCP elicitation (Claude
Code and Claude Desktop do) show the approve/deny dialog inline; on approval a scoped,
TTL'd grant is minted and the call proceeds.

## Quickstart (HTTP — a shared gateway on a company server)

```sh
delegent init --listen 0.0.0.0:8090
delegent target add …
delegent key mint --name alice-agent    # one key per developer/agent
delegent serve
```

Agents connect to `http://host:8090/mcp` with `Authorization: Bearer <agent key>` — the same
aggregate surface stdio serves. `/mcp/{target}` pins a single target for debugging.

This is a **single-operator** deployment: one human (or ops team) owns the instance, issues
keys, and receives every consent ask. Multi-operator routing, dashboards, and hosted
approval channels are the hosted product.

## Agents as targets (A2A)

An agent that publishes an [A2A Agent Card](https://a2a-protocol.org) is fronted exactly like
an MCP server: its skills become tools (`researcher__research_topic`), each call carries the
consent, policy, and receipts every tool call gets, and the agent's inbound secret lives only
in delegent.

```sh
delegent target add --kind a2a --id researcher --endpoint http://agents.internal:7103 \
    --credential <the agent's bearer> --mint-key
```

`--mint-key` also mints the key the agent uses when it is *itself* a consumer — when it calls
other targets through delegent. Point the agent's outbound calls at `http://host:8090/mcp`
with that key, and have it **echo the `X-Delegent-Session` header it was called with** on
every call it makes for that request (a request-scoped variable, where trace ids already
live). That one header is the whole integration:

- **With the header** the agent's grants are keyed per task: every call it makes is a child
  hop of the session that called it. The consent prompt shows the chain
  (`agent:researcher@mailer (working under claude-code@researcher) wants to send an email`),
  the child expires no later than its parent, revoking the parent's chain takes it down, and
  each hop spends one unit of delegation depth (`DELEGENT_MAX_DEPTH`, default 2) — a call
  past the limit is refused before anyone is asked.
- **Without it** the call is parentless: the agent's own key policy applies, the prompt says
  `registered agent 'researcher' — no parent task given`, and the human decides.

A skill takes free text, so per-skill policy is coarser than per-tool policy: the drafted
effect comes from the skill's name and tags, and the operator signs it like any tool. Long
tasks are polled, with state changes reaching the calling client as MCP progress; a task
still running after `DELEGENT_A2A_WAIT` (default 25s, under most clients' tool-call timeouts)
is handed back with its id for `get_task`, and a client that re-sends the same request is
attached to the running task rather than starting a second one. A task the agent parks on
`input-required` likewise comes back with a `get_task` handle to resume it.
`agents/demo.sh` in the repository stands up a four-agent walkthrough.

## Dashboard

```sh
delegent dashboard
```

A terminal dashboard over everything above — four tabs:

- **Targets** — drill into a target to edit its tool policy (cycle effects, edit scopes,
  mark tools refused, `I` re-introspects the upstream and drafts newly appeared tools) and
  to manage the operator entitlement per target: opt scopes in/out (an opt-out withholds the
  scope from every grant without deleting it) and `e` bulk-cycles the effect of every tool
  behind the selected scope. Edits apply LIVE to a running gateway — no restart.
- **Keys** — mint, revoke, **roll** (`R`: a fresh key under the same name, old one
  revoked; plaintext shown exactly once), and `c` sets the key's consent-channel policy
  (auto / console only / in-chat first / widget first — same presets as the hosted console).
- **Audit** — the activity log, filterable, with live tail.
- **Runs** (web dashboard, top bar) — one task at a time, live. The flow view draws you,
  the client, and every agent it reached as boxes, and animates each request and reply as a
  packet along the edge between them, with the message it carried; a box glows while its
  agent works and pulses amber while it waits on you. Replay plays a finished run again. A
  sequence diagram with the full payloads sits underneath.
- **Alerts** — pending consent asks as they happen (badge + terminal bell from any tab):
  approve with a per-scope picker + TTL/budget, or deny.

The dashboard finds a running gateway automatically — `serve` and `stdio` both register a
loopback admin address under `~/.delegent/run/` — and drives it over the admin API, so live
consent alerts work even when your only gateway is the stdio process Claude launched. With
nothing running it falls back to editing the files directly and says so in the status line.

## Approvals

Consent asks resolve through the first channel that works, console-of-last-resort:

1. **elicitation** — the agent's own client shows the dialog (stdio's happy path)
2. **telegram** — approve/deny buttons in your chat:
   ```sh
   delegent telegram setup --token <BotFather token> --bot-username my_bot   # serve must be running
   delegent telegram link                                                    # bind your chat
   ```
   Run ONE telegram poller per bot token — `serve` runs it; pass `--telegram` to `stdio`
   only when no serve (or other stdio instance) is already polling.
3. **CLI** — asks that outlive their call park durably; list and resolve them anytime:
   ```sh
   delegent approvals                       # requires a running serve
   delegent approvals approve creq_… --ttl 60
   delegent approvals deny creq_…
   ```

## What's on disk

Everything lives under `~/.delegent` (override: `--home` / `DELEGENT_HOME`):

| file | contents |
|---|---|
| `config.json` | listen address, admin token — display-safe settings |
| `identity.json` | this instance's ed25519 identity (public half = its address) |
| `master.key` | the sealing key (unless you use `DELEGENT_MASTER_KEY`) — **back it up** |
| `targets.json`, `agent_keys.json`, `entitlements.json`, … | configuration, plain diffable JSON |
| `adapters.json`, `advisors.json` | per-target tool classification + human scope descriptions |
| `secrets.sealed` | vendor credentials, sealed — useless without the master key |
| `receipts/<principal>.jsonl` | append-only, hash-chained, signed audit log |
| `events.jsonl` | the operator-facing activity log |

Receipts verify offline with the `delegent-proto` CLI from the protocol library — no gateway, no trust
in this binary required. Tools introspection drafts a classification per tool; anything it
can't classify is **refused until you classify it** in `adapters.json` (fail closed).

`DELEGENT_MAX_DEPTH` sets how many hops a human's grant may be handed down (default 2).

Config edits (targets, keys) are read at startup: restart `serve` — or let your MCP client
relaunch the stdio process — to apply them. Runtime approvals need no restart.

## Docker

From the repository root (the build needs both modules):

```sh
docker build -t delegent .
docker run -p 8090:8090 -v delegent-data:/data \
  -e DELEGENT_MASTER_KEY=$(openssl rand -base64 32) delegent
```

State persists in the `/data` volume; the container init-and-serves on `0.0.0.0:8090`. Manage
it with the same CLI: `docker exec <ctr> delegent target add …`.

## Not here (yet or by design)

- **OAuth for servers without dynamic client registration** — adding a server in the web
  dashboard with no token discovers its authorization server (401 → `WWW-Authenticate` →
  protected-resource metadata → RFC 8414 metadata), registers a client dynamically, and runs
  authorization-code + PKCE in your browser. An authorization server that publishes no
  `registration_endpoint` (GitHub, for one) needs a client you registered yourself, which the
  dashboard cannot do for you yet — paste a token for those.
- **Multi-operator, orgs, hosted channels, dashboards, the curated adapter registry** — the
  hosted product.
- **Cross-instance delegation** — the instance identity minted at `init` is its future
  address; the gateway-to-gateway protocol is on the roadmap.
