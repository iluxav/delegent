// Console consent: the third consent channel, for clients that can NEITHER elicit (Claude
// Code) NOR render the MCP Apps widget (Claude Desktop) — e.g. ChatGPT. Instead of a flat
// fail-closed denial, a guarded tool call PARKS a pending consent request, BLOCKS (exactly as
// the widget path blocks on request_access), and a human GRANTs it in the web console. On the
// grant the SAME broker mint path runs and the blocked call returns "Granted" so the model
// proceeds in the same turn; on deny or timeout the call fails closed.
//
// The console surface is reached over /api/consent/* (behind the console bearer): the API asks
// the Registry, which walks the live per-target gateways and reads/resolves their in-memory
// pending stores directly — one process serves both /api/* and /mcp/{target}.
package gateway

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/store"
)

// defaultConsentSyncWait is how long a console-mode tool call blocks for a SAME-TURN decision
// before returning "pending — retry shortly". It is short by design: the request persists as a
// durable consent_requests row, so a human can approve/deny it long after this window and the
// agent's retry then succeeds. defaultConsentRequestTTL is how long that persisted pending row
// stays approvable.
const (
	defaultConsentSyncWait   = 25 * time.Second
	defaultConsentRequestTTL = 30 * time.Minute
)

// consoleConsentFromEnv reads DELEGENT_CONSOLE_CONSENT once at construction. Console consent is
// ON by default; set the var to "off" to restore hard fail-closed for clients with no
// elicitation and no widget.
func consoleConsentFromEnv() bool {
	return !strings.EqualFold(os.Getenv("DELEGENT_CONSOLE_CONSENT"), "off")
}

// parseWait accepts a Go duration ("25s", "2m") or a bare integer number of seconds ("25");
// returns 0 when v is empty or unparseable.
func parseWait(v string) time.Duration {
	if v == "" {
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// consentSyncWaitFromEnv resolves how long a console call blocks for a same-turn decision:
// DELEGENT_CONSENT_SYNC_WAIT wins; DELEGENT_CONSOLE_DECISION_WAIT is a back-compat alias; the
// default is 25s. Both accept a Go duration or bare seconds.
func consentSyncWaitFromEnv() time.Duration {
	if d := parseWait(os.Getenv("DELEGENT_CONSENT_SYNC_WAIT")); d > 0 {
		return d
	}
	if d := parseWait(os.Getenv("DELEGENT_CONSOLE_DECISION_WAIT")); d > 0 {
		return d
	}
	return defaultConsentSyncWait
}

// consentRequestTTLFromEnv resolves how long a persisted pending request stays approvable:
// DELEGENT_CONSENT_REQUEST_TTL as a Go duration ("30m") or a bare integer number of MINUTES;
// the default is 30m.
func consentRequestTTLFromEnv() time.Duration {
	v := os.Getenv("DELEGENT_CONSENT_REQUEST_TTL")
	if v == "" {
		return defaultConsentRequestTTL
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Minute
	}
	return defaultConsentRequestTTL
}

// consentSyncWait is the effective per-gateway sync-block window (test-overridable via the
// syncWait field; falls back to the default when unset).
func (g *Gateway) consentSyncWait() time.Duration {
	if g.syncWait > 0 {
		return g.syncWait
	}
	return defaultConsentSyncWait
}

// consentRequestTTL is the effective persisted-pending lifetime (test-overridable via the
// requestTTL field; falls back to the default when unset).
func (g *Gateway) consentRequestTTL() time.Duration {
	if g.requestTTL > 0 {
		return g.requestTTL
	}
	return defaultConsentRequestTTL
}

// ---- serializable views for the API / SSE ----

// ScopeView is one grantable scope rendered for the console, with the advisor's human text.
type ScopeView struct {
	Scope    string   `json:"scope"`
	Human    string   `json:"human"`
	Risk     string   `json:"risk"`
	Warnings []string `json:"warnings,omitempty"`
}

// PendingView is a parked console-consent request as the web console sees it — everything a
// human needs to decide, and nothing redeemable (no widget_token, no connection id).
type PendingView struct {
	ID              string      `json:"id"`
	TargetID        string      `json:"target_id"`
	Principal       string      `json:"principal"`
	AgentName       string      `json:"agent_name"`
	Scopes          []ScopeView `json:"scopes"`
	Reason          string      `json:"reason"`
	Headline        string      `json:"headline,omitempty"` // the same legible line the in-chat dialogs show
	Intent          string      `json:"intent,omitempty"`   // the agent's declared why
	OverAskWarnings []string    `json:"over_ask_warnings,omitempty"`
	TTLOptions      []ttlOption `json:"ttl_options"`     // the grant-lifetime choices the console offers
	TTLDefaultMin   int         `json:"ttl_default_min"` // pre-selected option, in minutes
	CreatedAt       int64       `json:"created_at"`
	ExpiresAt       int64       `json:"expires_at"`
}

// ConsentEvent is a live change on the console-consent stream: a request appeared ("pending",
// View set) or cleared ("resolved", ID set). Owner is the request's principal (the target
// owner), used to filter the SSE stream per console user; it is not serialized to the client.
type ConsentEvent struct {
	Type  string       `json:"type"`
	Owner string       `json:"-"`
	ID    string       `json:"id,omitempty"`
	View  *PendingView `json:"view,omitempty"`
}

// ConsentHub is a tiny in-process pub/sub the gateways publish console park/resolve events to
// and the API's SSE handler subscribes to. Owned by the Registry (one per process); slow or
// gone subscribers are never allowed to block a publish (events drop for a full buffer).
type ConsentHub struct {
	mu   sync.Mutex
	seq  int
	subs map[int]chan ConsentEvent
}

func newConsentHub() *ConsentHub { return &ConsentHub{subs: map[int]chan ConsentEvent{}} }

// subscribe returns a receive channel and a cancel func that unsubscribes and closes it.
func (h *ConsentHub) subscribe() (<-chan ConsentEvent, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	id := h.seq
	h.seq++
	ch := make(chan ConsentEvent, 32)
	h.subs[id] = ch
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(ch)
		}
	}
}

func (h *ConsentHub) publish(e ConsentEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.subs {
		select {
		case ch <- e:
		default: // a full/slow subscriber never blocks the gateway
		}
	}
}

func (g *Gateway) publishConsent(e ConsentEvent) {
	if g.hub != nil {
		g.hub.publish(e)
	}
}

// ---- the console consent view + resolve, on the Gateway ----

// pendingView renders one pending record as a PendingView, deriving the requesting-agent name
// and the per-scope human/risk/warnings the same way widgetRequestAccess does.
func (g *Gateway) pendingView(pc pendingConsent) PendingView {
	cr := g.cp.DescribeConsent(pc.Principal, pc.Scopes, pc.Reason)
	scopes := make([]ScopeView, len(cr.Scopes))
	for i, sc := range cr.Scopes {
		scopes[i] = ScopeView{Scope: sc.Scope, Human: sc.Human, Risk: sc.Risk, Warnings: sc.Warnings}
	}
	return PendingView{
		ID: pc.ID, TargetID: g.targetID, Principal: pc.Principal,
		AgentName:       g.br.AgentDisplayName(g.resumeSession(pc.ConnID)),
		Scopes:          scopes,
		Reason:          pc.Reason,
		Headline:        pc.Headline,
		Intent:          pc.Intent,
		OverAskWarnings: cr.OverAskWarnings,
		TTLOptions:      ttlOptions(),
		TTLDefaultMin:   ttlDefault().Minutes,
		CreatedAt:       pc.CreatedAt, ExpiresAt: pc.ExpiresAt,
	}
}

// PendingViews returns this gateway's live, unused pending consents whose principal (the target
// owner) matches owner — or all of them when owner is empty.
func (g *Gateway) PendingViews(owner string) []PendingView {
	var out []PendingView
	for _, pc := range g.pending.listLive() {
		if owner != "" && pc.Principal != owner {
			continue
		}
		out = append(out, g.pendingView(pc))
	}
	return out
}

// consoleDecision is a human's console decision. Empty granted (or Deny) is a decline.
type consoleDecision struct {
	owner      string // authenticated console operator; must match the record's principal ("" = no check)
	granted    []string
	ttlMinutes int
	budgetUSD  float64
}

// ResolvePending applies a human's console decision to pending id: it burns the nonce (no
// widget binding — the console bearer + owner filter already authorized it) and runs the SAME
// mint path the widget's submit uses, which resolves the record's done channel so the blocked
// console-mode vendor call returns in the same turn. ok=false when the id is unknown, expired,
// or already resolved — safe to call from the Registry without knowing which gateway holds it.
func (g *Gateway) ResolvePending(id string, d consoleDecision) (ok, granted bool, message string) {
	pc, err := g.pending.consumeByID(id, d.owner)
	if err != nil {
		return false, false, err.Error()
	}
	var answer *controlplane.ConsentAnswer
	if len(d.granted) > 0 && !onlyEmpty(d.granted) {
		ttl := ttlClampMinutes(d.ttlMinutes)
		budget := d.budgetUSD
		if budget <= 0 {
			budget = 1
		}
		answer = &controlplane.ConsentAnswer{Granted: d.granted, TTLMinutes: ttl, BudgetUSD: budget}
	}
	// mintPending runs the shared broker grant path: on GRANT it mints (or augments) the session
	// AND binds it to pc.ConnID via setSession, so a LATER retry on the same connection resumes it
	// even when no call was blocked here. It also resolves pc.done so a same-turn waiter unblocks.
	granted, message = g.mintPending(pc, answer)
	if granted {
		g.finalizeConsentRow(id, "approved", answer.Granted, answer.TTLMinutes, answer.BudgetUSD)
	} else {
		g.finalizeConsentRow(id, "denied", nil, 0, 0)
	}
	g.publishConsent(ConsentEvent{Type: "resolved", Owner: pc.Principal, ID: id})
	log.Printf("[delegent] console consent %s resolved via /api/consent — granted=%v %s", id, granted, message)
	return true, granted, message
}

// onlyEmpty reports whether every scope in gs is blank (defensive against a decision body of
// [""] which must read as a deny, not a grant of nothing).
func onlyEmpty(gs []string) bool {
	for _, s := range gs {
		if strings.TrimSpace(s) != "" {
			return false
		}
	}
	return true
}

// consoleConsentBlock parks a guarded VENDOR call's consent as pending and BLOCKS until a human
// GRANTs/DENYs it in the web console (fail closed on deny/timeout). The vendor tool is NOT
// executed here — the model retries it after a grant, which this connection then holds.
func (g *Gateway) consoleConsentBlock(ctx context.Context, connID, tool string, scopes []string, meta callMeta) *mcp.CallToolResult {
	return g.blockOnConsole(ctx, connID, "'"+tool+"'", "tool: "+tool, scopes, "Retry '"+tool+"' now.", meta)
}

// consoleRequestAccess is request_access on a console-mode client: it blocks on the same human
// GRANT at the console, then returns the outcome so the model proceeds in the same turn.
func (g *Gateway) consoleRequestAccess(ctx context.Context, connID, reason string, scopes []string) *mcp.CallToolResult {
	return g.blockOnConsole(ctx, connID, "the requested access", reason, scopes, "The granted access is now held for this session.", callMeta{Target: g.targetID, Intent: reason})
}

// blockOnConsole is the shared DURABLE console-consent core: describe → park (in-memory AND as a
// persisted consent_requests row) → publish → BLOCK for a SHORT sync window. If a human decides
// within the window the call returns granted/denied in the same turn; otherwise it returns a
// NON-error "pending — retry shortly" and the request PERSISTS, so a human can approve/deny it
// anytime (Registry → ResolvePending), which mints the session bound to this connection so the
// agent's retry succeeds. Unlike the old flow it never fails closed on the timeout and never
// abandons the record — the persisted row (and its TTL) is the durable state.
func (g *Gateway) blockOnConsole(ctx context.Context, connID, label, reason string, scopes []string, retryHint string, meta callMeta) *mcp.CallToolResult {
	principal := g.principalOf(ctx)
	headline := consentHeadline(g.br.AgentDisplayName(g.resumeSession(connID)), meta) + "\n"
	cr := g.cp.DescribeConsent(principal, scopes, reason)
	displayHeadline := strings.TrimSuffix(headline, "\n")
	if len(cr.Scopes) == 0 {
		log.Printf("🔒 %s DENIED — console consent: nothing grantable for %s", label, principal)
		return toolError("🔒 DELEGENT: " + label + " needs [" + strings.Join(scopes, ", ") + "] — " + principal +
			" does not hold: " + strings.Join(cr.Ungrantable, ", ") + ", so no consent can grant it.")
	}

	// Reuse the live record on a retry (dedup by principal+conn+scopeset), or mint a fresh one
	// with the durable request TTL. Persisting upserts by id, so a retry updates the SAME row.
	pc := g.pending.findOrCreateTTL(principal, connID, scopes, reason, g.consentRequestTTL())
	// The same legible display the in-chat dialogs render travels with the record: onto the
	// live view (console card) and the durable row (approvals history, telegram) — parity.
	g.pending.setDisplay(pc.ID, displayHeadline, meta.Intent)
	pc.Headline, pc.Intent = displayHeadline, meta.Intent
	g.pending.setWaiting(pc.ID, true)
	view := g.pendingView(pc)
	g.persistPending(pc, view.AgentName)
	g.publishConsent(ConsentEvent{Type: "pending", Owner: pc.Principal, ID: pc.ID, View: &view})
	log.Printf("🔒 %s needs [%s] — console consent PENDING (request %s, agent %s); blocking up to %s for a same-turn decision (persisted, approvable for %s)",
		label, strings.Join(scopes, ", "), pc.ID, view.AgentName, g.consentSyncWait(), g.consentRequestTTL())

	// Live wait telemetry: a call that supplied a progressToken sees WHY it is blocked, and a
	// heartbeat every few seconds while the sync window runs. No-op without a token.
	emitProgress(ctx, "⏳ waiting for human approval ("+pc.ID+") — a person must approve ["+strings.Join(scopes, ", ")+"]")
	stopBeat := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stopBeat:
				return
			case <-tick.C:
				emitProgress(ctx, "⏳ still waiting for human approval ("+pc.ID+")")
			}
		}
	}()

	outcome, decided := awaitConsent(ctx, pc.done, g.consentSyncWait())
	close(stopBeat)
	g.pending.setWaiting(pc.ID, false)
	if !decided { // close the race between the timer firing and a just-landed resolve
		select {
		case outcome = <-pc.done:
			decided = true
		default:
		}
	}

	// The agent abandoned the call (MCP cancellation, or the connection died) with no decision
	// landed: WITHDRAW the ask — there is no one left to grant to, and a ghost ask a human can
	// approve into the void is worse than none. A decision that raced the cancellation wins
	// (withdraw skips used records). The durable row is finalized "cancelled" for the audit
	// trail, and subscribers (dashboard badge, console) see it resolve.
	if !decided && ctx.Err() != nil {
		if g.pending.withdraw(pc.ID) {
			g.finalizeConsentRow(pc.ID, "cancelled", nil, 0, 0)
			g.publishConsent(ConsentEvent{Type: "resolved", Owner: pc.Principal, ID: pc.ID})
			log.Printf("🚮 %s console consent %s WITHDRAWN — the agent cancelled before a human decided", label, pc.ID)
		}
		return toolError("🔒 DELEGENT: the request was cancelled before a human decided — nothing was granted.")
	}

	if decided && outcome.granted {
		log.Printf("✅ %s console consent %s GRANTED same-turn — model proceeds now", label, pc.ID)
		return text(headline + "✅ DELEGENT: a human granted access at the console. " + outcome.message + " " + retryHint)
	}
	if decided {
		log.Printf("🔒 %s console consent %s DENIED at the console", label, pc.ID)
		return toolError("🔒 DELEGENT: a human DENIED " + label + " at the console — no access. " + outcome.message)
	}
	// No same-turn decision: DO NOT abandon or expire — the request stays pending and approvable.
	log.Printf("⏳ %s console consent %s still PENDING after %s — returning retry-shortly (approvable for %s)", label, pc.ID, g.consentSyncWait(), g.consentRequestTTL())
	return text(headline + "⏳ DELEGENT: access request PENDING human approval in the console (request " + pc.ID + ") — NOT granted yet. " +
		"Retry " + label + " shortly; once a human approves it there, the retry will succeed.")
}

// persistPending upserts the in-memory console record as a durable consent_requests row (status
// pending). No-op when no store is wired (unit tests without a store). Best-effort: a store error
// is logged, not surfaced — the in-memory record still drives the same-turn wait.
func (g *Gateway) persistPending(pc pendingConsent, agentName string) {
	if g.st == nil {
		return
	}
	r := &store.ConsentRequest{
		ID: pc.ID, TargetID: g.targetID, Principal: pc.Principal, AgentName: agentName,
		Scopes: pc.Scopes, Reason: pc.Reason, Status: "pending",
		Headline: pc.Headline, Intent: pc.Intent,
		CreatedAt: pc.CreatedAt, ExpiresAt: pc.ExpiresAt,
	}
	if err := g.st.PutConsentRequest(context.Background(), r); err != nil {
		log.Printf("[delegent] could not persist console consent request %s: %v", pc.ID, err)
		return
	}
	if g.notifier != nil {
		// async so a slow channel (telegram round-trip) never delays the consent wait itself
		go g.notifier.ConsentParked(r)
	}
}

// finalizeConsentRow updates the persisted row for a resolved decision (approved/denied) with the
// decided scopes and resolution time. Best-effort; no-op without a store.
func (g *Gateway) finalizeConsentRow(id, status string, decided []string, ttlMinutes int, budgetUSD float64) {
	if g.st == nil {
		return
	}
	ctx := context.Background()
	r, err := g.st.GetConsentRequest(ctx, id)
	if err != nil {
		return // row may predate persistence or already be gone — harmless
	}
	r.Status = status
	r.DecidedScopes = decided
	r.TTLMinutes = ttlMinutes
	r.BudgetUSD = budgetUSD
	r.ResolvedAt = nowMillis()
	if err := g.st.PutConsentRequest(ctx, r); err != nil {
		log.Printf("[delegent] could not finalize console consent request %s: %v", id, err)
	}
}
