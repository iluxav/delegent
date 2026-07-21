# Delegent

**Consent-bound authority for AI agents.** Delegent puts a gateway between your agents and
the MCP servers they use: every tool call is checked against entitlements, gated on human
consent, and recorded in a tamper-evident, signed receipt chain — so an agent can hold
*narrow, expiring, auditable* authority instead of your raw credentials.

This repository is the open implementation, in two Go modules:

| module | what it is |
|---|---|
| [`delegent.dev/protocol`](protocol/) | The math: capability slips, the attenuation/verification algebra, receipt hash chains. **Zero dependencies** (stdlib only) — any party can verify a chain or an audit trail with this package and a public key. Ships the `delegent-proto` CLI. |
| [`delegent.dev/gateway`](gateway/) | The runnable product: a single-binary, single-operator MCP gateway (stdio + HTTP) with JSON-file state, sealed secrets, consent via elicitation / Telegram / CLI, and per-principal signed receipts. Ships the `delegent` binary. |

The hosted platform at [delegent.dev](https://delegent.dev) — teams, dashboards, hosted
approval channels, the curated adapter registry — runs this same engine.

## Quick start

```sh
curl -fsSL https://delegent.dev/install.sh | sh    # or: go install delegent.dev/gateway/cmd/delegent@latest
delegent init
delegent target add --id github --endpoint https://your-mcp.example/mcp --credential <token>
delegent key mint --name laptop
```

Point your MCP client (Claude Code, Claude Desktop, Cursor, …) at `delegent stdio`
and every vendor tool arrives consent-gated. Full walkthrough, HTTP/Docker deployment, and
the approvals flow: [gateway/README.md](gateway/README.md).

Verify a receipt trail offline — no gateway, no trust in this repo's binaries required:

```sh
go install delegent.dev/protocol/cmd/delegent-proto@latest
delegent-proto verify-receipts --receipts receipts.jsonl --pub <operator pubkey>
```

## Why the split

The protocol module is deliberately boring: no I/O, no state, no dependencies. That is the
trust anchor — the gateway (and the hosted platform, and anything you build) enforce exactly
the algebra you can read and run yourself. The gateway module carries the real-world
machinery and depends on the protocol, never the other way around.

## License

Apache-2.0 — see [LICENSE](LICENSE).
