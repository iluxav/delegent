# Demo agents — agents as targets, end to end

Four small A2A agents that show Delegent fronting *agents* the way it fronts MCP servers, and
agents calling each other **through** Delegent with the whole chain consented and receipted.
Nothing here ships; it is a walkthrough harness for [`PLAN-A2A.md`](../PLAN-A2A.md).

| agent | port | skill | does |
|---|---|---|---|
| librarian | 7101 | `search_docs` | leaf: answers from a canned corpus (solar, delegent, coffee) |
| mailer | 7102 | `send_email` | leaf: "sends" email by logging it |
| researcher | 7103 | `research_topic` | asks the librarian **through Delegent**; emails the summary via the mailer when asked to |
| assistant | 7104 | `write_report` | delegates to the researcher through Delegent — a second hop |
| web (MCP server) | 7105 | `search_web`, `fetch_page` | the open web: DuckDuckGo results and a page's readable text, no API key |

`web` is not an agent but an ordinary MCP server (`cmd/web-mcp`), registered like any other
target. With it registered the researcher searches the web first, reads the top result, and
only then checks the librarian's archive — so "research X" is real research, through the
gateway, with `web:read`-style consent like everything else. Without it the researcher falls
back to the archive alone.

Every agent publishes an Agent Card at `/.well-known/agent-card.json`, requires its own
inbound secret (`secret-<role>`; only Delegent holds it), and — the one integration rule —
**echoes the `X-Delegent-Session` header it was called with on every call it makes to
Delegent**. That is what lets Delegent key the agent's grants per task and show the operator
`claude-code@assistant → agent:assistant@researcher → …` on the consent prompt.

## Run it

```sh
agents/demo.sh            # build, init ~/.delegent-a2a-demo, start agents + serve, register targets
agents/demo.sh stop
```

The script prints a `claude mcp add --transport http …` line: connect Claude Code over HTTP so
the agents and your session share one `serve` process (the JSON-file store is single-process).
Then ask Claude:

> use researcher__research_topic to research solar panels and email the summary to bob@acme.example

or, from the shell, without a chat client:

```sh
~/.delegent-a2a-demo/bin/demo-call --key-file ~/.delegent-a2a-demo/keys/harness.key --list
~/.delegent-a2a-demo/bin/demo-call --key-file ~/.delegent-a2a-demo/keys/harness.key \
  researcher__research_topic '{"message":"research solar panels and email the summary to bob@acme.example"}'
```

What you will see, in order:

1. **Your call needs consent.** Claude Code shows the elicitation dialog inline; `demo-call`
   has none, so the ask parks in the console — approve it in the dashboard's Alerts tab
   (`http://127.0.0.1:8091/`) or with `delegent approvals --home ~/.delegent-a2a-demo`.
2. **The researcher asks for the librarian.** A second ask, from the researcher's own key,
   reading `agent:researcher@librarian (working under claude-code@researcher) wants to search
   the document archive`. Approve it.
3. **The researcher asks for the mailer** — `✉ send an email — external`. Approve or deny;
   the researcher reports either way.
4. The summary comes back to you, with each hop's `context_id`.

Try `assistant__write_report` for a three-hop chain. Open the **Runs** page in the dashboard
(top bar) first: it draws the run live — boxes for you, the client and every agent, with each
request and reply animated along the edges as it happens, and the approvals pulsing until you
decide. The agents pace their work (`DEMO_PACE`, default 2s per step; `--pace 0` for instant)
so there is something to watch. The Audit tab has the raw events: every one carries the parent
session it ran under, and every grant receipt says `ok; under sess_…`.

Things worth trying:

- **Depth.** `serve` runs with `DELEGENT_MAX_DEPTH=3` (harness → assistant → researcher →
  leaf). Restart it with `DELEGENT_MAX_DEPTH=1` and the researcher's call to the librarian is
  refused *before anyone is asked*: "delegation depth exhausted". Every hop spends one.
- **Parentless.** Call with an agent's key and no session:
  `demo-call --key-file …/keys/researcher.key librarian__search_docs '{"message":"delegent"}'`.
  The prompt says `registered agent 'researcher' — no parent task given, acting on its own`.
- **Revocation.** `revoke` with `chain: true` on your session takes every hop it spawned down
  with it, on every target.

## With a real model

Each agent can run on a local Ollama instead of its script: the model sees the tools Delegent
exposes to that agent and picks them itself, and every pick still goes through consent.

```sh
DEMO_BRAIN=ollama DEMO_MODEL=qwen3.5:9b agents/demo.sh
```

Small models are erratic with tool calling; `llama3.2:3b` works often, `qwen3.5:9b` more
reliably. The scripted brain is the default because a deterministic chain is easier to read.

## Layout

- `cmd/demo-agent` — the four roles (`--all`, or `--role researcher`); flags for ports,
  secrets, keys, brain.
- `cmd/demo-call` — a shell harness playing Claude Code's part (one tool call, with retries
  while consent is pending).
- `cmd/web-mcp` — the web MCP server: `search_web` (DuckDuckGo HTML results) and
  `fetch_page` (readable text of a URL), behind a bearer only Delegent holds.
- `internal/a2aserver` — a minimal A2A host: card, bearer check, async tasks, `tasks/get`.
- `internal/dclient` — the consumer side: an MCP client on Delegent's `/mcp` with the
  agent's key, echoing the session header.
- `internal/brains` — the scripted behaviours and the Ollama loop.
