# Plan: agents as targets (A2A)

Status: 2026-09-24. Built: the upstream interface, Phase 1 (A2A targets through MCP, `--kind
a2a`), the escalation fix, and item 6 (linking hops by header, with the parentless rule and a
depth limit). Demo: `agents/demo.sh`. Not built: items 5 (a native A2A endpoint on delegent),
7 (per-caller discovery), 8 (remembered decisions).

## Where this starts

Today a consumer agent (Claude Code, Cursor, an in-house agent) connects to delegent with an
access key. When it calls a tool, delegent checks policy and asks a human if consent is
required. It then mints a slip, swaps in the real secret, and calls the real MCP server. The
consumer never holds the secret.

The same company also runs agents of its own, each publishing an A2A Agent Card and needing
some credential. The idea is to proxy them exactly like MCP servers:

1. **Agents are targets.** Add an agent's URL and secret and set a policy. Consumers call it
   through delegent with their own key, with consent where required.
2. **Every agent is also a consumer.** All traffic between agents goes through delegent.
   Agents can't bypass it, because only delegent holds each agent's real secret.

Adoption cost per agent: point outbound endpoints at delegent with an access key, store the
agent's real inbound secret in delegent, and forward one header (the delegent session id) from
each inbound request to every outbound call made for it. The header is the only code change.
An agent that omits it still works, but its calls are parentless (item 6).

## Authority rules

- **Effective permission on any call** = the chain from the human ∩ the caller's own key policy
  ∩ the target's policy. Delegent sees every hop, so it is the one place that can compute this.
- **Narrow (automatic):** A can hand B a strictly weaker slip without asking anyone. The damage
  is capped at what A could already do, even if A is prompt-injected.
- **Consent can only be tightened.** If the human's grant to A requires consent for writes, no
  child slip can drop that requirement. The prompt goes to the human, not to A.
- **B's own key adds nothing while B works for A.** B gets the overlap of its own rights and
  A's chain, never the union. This closes the confused-deputy hole.
- **Escalate (human only):** if neither B nor A holds what B needs, the human at the root is
  asked, and A is skipped. The grant is:
  - tied to the current run, with an expiry no later than B's session;
  - not passable on (depth 0), so B cannot pass it to C;
  - recorded in the receipts as an escalation linked to B's chain.
  The prompt shows the whole chain: task → A → B → wanted action.
- **Loops and fan-out:** delegent enforces a depth limit and a budget per original request.

## Gap found in the current code

Escalated grants **can** be passed on today, which breaks the rule above:

- **Ancestor path** (`gateway/broker/broker.go`, `mintFrom`): the new session keeps the
  requester's depth (`depth := r.Depth`), so B can `narrow_access` it to C. Its expiry follows
  the ancestor's chain, not the run.
- **Human path** (`Escalate`, `b.Open(ss.Principal, …)`): mints a brand-new *root* session.
  `MintFor` hardcodes `Depth: 2` (`gateway/controlplane/controlplane.go`), it has no parent, and
  the handle only comes back inside the message text.
- No test covers the human path. The two escalation tests in `broker_test.go` cover the ancestor
  path only.

Fix:
1. Mint every escalated grant with `Depth: 0`.
2. Cap its expiry at the requester's session expiry, or a short TTL if sooner.
3. On the human path, record the requester's session as the parent or "escalated-from" link
   instead of opening an unrelated root session.
4. Add a test that escalates to the human, narrows the result, and expects a refusal.

## Phase 1: agents as targets, called through the existing MCP side

1. **An upstream interface.** Today `forward()` calls `g.upstream.CallTool` directly
   (`gateway/gateway.go`), and nothing branches on `Target.Kind` (`"rest"` is declared but
   unused). Pull `ListTools`/`CallTool` behind an interface: MCP is the current implementation,
   A2A the second, as `Kind: "a2a"`.
2. **Inspecting agents.** Fetch `/.well-known/agent-card.json` and turn each skill into a draft
   entry, using the same review-and-sign flow as tools (`introspect`). Map the card's
   `securitySchemes` onto the existing credential kinds (`static_bearer`, `oauth2`,
   `query_param`).
3. **An A2A client:**
   - `message/send` for quick replies;
   - `message/stream`, `tasks/get` and `tasks/cancel` for long tasks.

   Map the task states onto what delegent already has:
   - `working` → progress notifications;
   - `input-required` → return the question to the caller;
   - `auth-required` → the consent flow.
4. **How agents appear to consumers:** each skill becomes an MCP tool, `agent__skill`, in the
   aggregate. MCP-only clients (Claude Code, Cursor) can then call agents unchanged.

## Phase 2: agents calling agents natively

5. **An A2A endpoint on delegent.** Serve a rewritten Agent Card per proxied agent at
   `/a2a/{target}`: its URL points to delegent and its auth is a delegent key. Proxy the
   JSON-RPC messages, with policy applied on each message and each task.
6. **Linking hops.** Every outbound call to delegent carries two things: the agent's access
   key (required, says who the agent is) and a session id (optional, says which job it is
   working on). Delegent adds the id as an `X-Delegent-Session` header when it forwards a
   call to an agent; the agent's one job is to send it back on every call it makes for that
   request (a request-scoped variable, the same place trace ids live). Frameworks that
   auto-propagate tracing headers can carry it in `baggage` with no code at all.

   - **Session id present:** attribution is exact. Every grant is tied to that session, so
     two concurrent jobs in the same agent get separate sessions with separate grants.
     Delegent intersects the agent's key policy with the session's chain, tightens consent,
     and links the receipts back to the human.
   - **Session id absent:** the call is parentless. It runs under the agent's own key
     policy, which the operator sets, and typically requires human consent for anything
     sensitive. No inference, no guessing: the receipt records it as a root call by that
     agent. If the agent is also a registered target (it has an inbound side), the consent
     prompt says so, because it is probably working for someone and did not say who.

   The parentless case is deliberately blunt. An agent that never forwards the header loses
   the audit link to the human and lands every sensitive call on the operator, which is the
   right pressure toward adding the header.
7. **Per-caller discovery.** Each caller sees the list of agents with its own status for each
   (allowed, asks first, denied). Beyond a few dozen agents, expose a `find_agent` search over
   the same list instead of listing everything.
8. **Remembered decisions.** Consent answers are "once", "for this task", or "always for A→B,
   these skills", and "always" becomes policy. Otherwise consent fatigue sets in.

## Open questions

- **Precision.** Skills take free text, so a message can't be classified the way a tool call
  can: "handle refunds" might read or might refund $5,000. Policy is per skill and per agent,
  with the effect level set by the operator, and the consent prompt shows the actual message.
  This is coarser than MCP tool policy; say so up front.
- **Who approves a call between agents:** the operator of the original request, the target
  agent's owner, or both? The target owner's policy always applies, but consent routing needs
  a decision.
- **Standards:** mapping slips onto the `Agent-Delegation` header
  (draft-hamr-oauth-agent-delegation) would let agents outside delegent verify the chain.
- **Inferring the parent.** Delegent proxies each agent's inbound tasks too, so it could
  guess which open task a header-less call belongs to. Dropped for v1 in favor of the
  parentless rule; revisit only if header forwarding proves too hard for real agents.

## Order

1. The upstream interface.
2. Phase 1: A2A targets through MCP.
3. The escalation fix.
4. Phase 2.

Phase 1 is useful by itself and reuses nearly everything. Phase 2 is the demo nobody else has:
three agents, each forwarding one header, where C's action traces back to the human through
verified receipts.
