# delegent-gateway — the local Delegent gateway

A single-binary, single-operator MCP gateway: put it in front of the MCP servers your agents
use and every tool call passes through **entitlements, human consent, and tamper-evident
receipts** before it reaches a vendor. No database, no account — state is plain JSON files in
one directory, secrets sealed with a master key only you hold.

This is the same engine the hosted Delegent product runs. The protocol math it enforces —
capability slips, the authorization algebra, receipt hash chains — lives in the stdlib-only
[`delegent.dev/protocol`](../protocol) library, so anyone can verify what this gateway does.

## Install

```sh
go install delegent.dev/gateway/cmd/delegent-gateway@latest
```

## Quickstart (stdio — Claude Code, Claude Desktop, Cursor, …)

```sh
delegent-gateway init
delegent-gateway target add --id github --endpoint https://your-mcp-server.example/mcp --credential <upstream token>
delegent-gateway key mint --name laptop        # prints the agent key ONCE
```

Then point your MCP client at the binary instead of at the vendors. Claude Code
(`.mcp.json`) / Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "delegent": {
      "command": "delegent-gateway",
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
delegent-gateway init --listen 0.0.0.0:8090
delegent-gateway target add …
delegent-gateway key mint --name alice-agent    # one key per developer/agent
delegent-gateway serve
```

Agents connect to `http://host:8090/mcp` with `Authorization: Bearer <agent key>` — the same
aggregate surface stdio serves. `/mcp/{target}` pins a single target for debugging.

This is a **single-operator** deployment: one human (or ops team) owns the instance, issues
keys, and receives every consent ask. Multi-operator routing, dashboards, and hosted
approval channels are the hosted product.

## Approvals

Consent asks resolve through the first channel that works, console-of-last-resort:

1. **elicitation** — the agent's own client shows the dialog (stdio's happy path)
2. **telegram** — approve/deny buttons in your chat:
   ```sh
   delegent-gateway telegram setup --token <BotFather token> --bot-username my_bot   # serve must be running
   delegent-gateway telegram link                                                    # bind your chat
   ```
   Run ONE telegram poller per bot token — `serve` runs it; pass `--telegram` to `stdio`
   only when no serve (or other stdio instance) is already polling.
3. **CLI** — asks that outlive their call park durably; list and resolve them anytime:
   ```sh
   delegent-gateway approvals                       # requires a running serve
   delegent-gateway approvals approve creq_… --ttl 60
   delegent-gateway approvals deny creq_…
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

Receipts verify offline with the `delegent` CLI from the core library — no gateway, no trust
in this binary required. Tools introspection drafts a classification per tool; anything it
can't classify is **refused until you classify it** in `adapters.json` (fail closed).

Config edits (targets, keys) are read at startup: restart `serve` — or let your MCP client
relaunch the stdio process — to apply them. Runtime approvals need no restart.

## Docker

From the repository root (the build needs both modules):

```sh
docker build -t delegent-gateway .
docker run -p 8090:8090 -v delegent-data:/data \
  -e DELEGENT_MASTER_KEY=$(openssl rand -base64 32) delegent-gateway
```

State persists in the `/data` volume; the container init-and-serves on `0.0.0.0:8090`. Manage
it with the same CLI: `docker exec <ctr> delegent-gateway target add …`.

## Not here (yet or by design)

- **OAuth acquisition flow** — targets whose credential is an OAuth 2.1 TokenSet refresh
  automatically, but the interactive connect/consent wizard that obtains one is currently
  hosted-product-only. Static bearer / query-param credentials cover most local setups.
- **Multi-operator, orgs, hosted channels, dashboards, the curated adapter registry** — the
  hosted product.
- **Cross-instance delegation** — the instance identity minted at `init` is its future
  address; the gateway-to-gateway protocol is on the roadmap.
