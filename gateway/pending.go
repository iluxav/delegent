package gateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

// pendingTTL is how long a widget consent request stays answerable. The request_id is a
// single-use nonce: short-lived and consumed atomically, so a replayed or stale widget
// submission can never mint a second grant.
const pendingTTL = 5 * time.Minute

// consentOutcome is the human's decision as submit_consent_decision resolved it — the exact
// text a request_access call blocked on this record should return so the model proceeds in
// the same turn.
type consentOutcome struct {
	granted bool
	message string
}

// pendingConsent is one consent ask awaiting the human's decision in the MCP Apps widget:
// which principal asked, on which connection, for which scopes, and why. It is minted when a
// widget-capable session needs consent and consumed exactly once by submit_consent_decision.
type pendingConsent struct {
	ID string
	// WidgetToken is a second secret the model never sees: it travels ONLY in the
	// request_access result's _meta (the widget-only channel). The model-visible channels —
	// content and structuredContent — carry the ID but never this token, so knowing the ID
	// alone cannot redeem the request.
	WidgetToken string
	Principal   string
	ConnID      string
	Scopes      []string
	Reason      string
	// Headline and Intent are the DISPLAY fields for the widget: the legible action+risk headline
	// (built via consentHeadline) and the agent's declared intent, stashed from the originating
	// guarded call so serveConsentToken can render the same headline the elicitation dialog shows.
	// Empty when the request had no originating tool call (a direct request_access) — fail-soft.
	Headline  string
	Intent    string
	CreatedAt int64 // unix millis
	ExpiresAt int64 // unix millis
	used      bool
	// done delivers the decision to a request_access call blocked on this record. Created
	// EXACTLY ONCE, in findOrCreate's mint branch — every copy findOrCreate/consume hands out
	// shares this same channel, so the vendor-call-denial record and the model's follow-up
	// request_access resolve through one channel. Buffered (1) so resolving never blocks even
	// with no waiter.
	done chan consentOutcome
	// waiting is true while a request_access call is blocked on done — the signal
	// submit_consent_decision uses to tell the widget the outcome was delivered inline (so
	// the widget suppresses its ui/message nudge).
	waiting bool
}

// resolve delivers the decision to whoever is blocked on this record's done channel,
// without ever blocking the submitter. The channel is buffered, so even a raced/late
// resolve parks the outcome for the waiter's final drain.
func (pc pendingConsent) resolve(o consentOutcome) {
	if pc.done == nil {
		return
	}
	select {
	case pc.done <- o:
	default:
	}
}

// errConsentBinding marks a redemption whose request_id exists but whose widget token,
// connection, or principal did not match the record — i.e. a forgery attempt, not a stale
// retry. Callers must surface ONE uniform message for every binding failure (the internal
// error stays distinct for logs) so a forger learns nothing about which check tripped.
var errConsentBinding = errors.New("consent binding mismatch")

// pendingStore is the in-memory ledger of widget consent nonces. Entries are pruned on every
// create and rejected on consume when expired or already used — fail closed on anything
// unrecognized.
type pendingStore struct {
	mu    sync.Mutex
	now   func() int64
	newID func() string
	m     map[string]*pendingConsent
}

func newPendingStore(now func() int64, newID func() string) *pendingStore {
	return &pendingStore{now: now, newID: newID, m: map[string]*pendingConsent{}}
}

// findOrCreate returns the live, unused pending request for this (principal, connection,
// scope-set) if one exists — so the guarded tool call and the model's follow-up
// request_access share ONE nonce — or mints a fresh one. Returns a copy; the store's record
// is only ever mutated under its own lock.
func (p *pendingStore) findOrCreate(principal, connID string, scopes []string, reason string) pendingConsent {
	return p.findOrCreateTTL(principal, connID, scopes, reason, pendingTTL)
}

// findOrCreateTTL is findOrCreate with an explicit record lifetime. Widget consent keeps the
// 5-minute pendingTTL; durable CONSOLE consent passes the longer request TTL so the in-memory
// record stays around for a human who approves anytime (its DB row is the real durable state).
func (p *pendingStore) findOrCreateTTL(principal, connID string, scopes []string, reason string, ttl time.Duration) pendingConsent {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for id, pc := range p.m {
		if now > pc.ExpiresAt {
			delete(p.m, id)
		}
	}
	for _, pc := range p.m {
		if !pc.used && pc.Principal == principal && pc.ConnID == connID && sameScopeSet(pc.Scopes, scopes) {
			return *pc
		}
	}
	pc := &pendingConsent{
		ID: p.newID(), WidgetToken: p.newID(), Principal: principal, ConnID: connID,
		Scopes: append([]string{}, scopes...), Reason: reason,
		CreatedAt: now, ExpiresAt: now + ttl.Milliseconds(),
		done: make(chan consentOutcome, 1),
	}
	p.m[pc.ID] = pc
	return *pc
}

// setWaiting flags whether a request_access call is currently blocked on this record's done
// channel. A no-op for ids no longer in the store (consumed records stay until pruned, so the
// waiter's cleanup after a grant still finds them — harmlessly).
func (p *pendingStore) setWaiting(id string, w bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pc, ok := p.m[id]; ok {
		pc.waiting = w
	}
}

// setDisplay records the legible headline + intent on a live record so the widget's bridged
// resource-read (serveConsentToken) renders the same headline the elicitation dialog shows. A
// no-op for ids no longer in the store — purely additive display data, never gating.
func (p *pendingStore) setDisplay(id, headline, intent string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pc, ok := p.m[id]; ok {
		pc.Headline = headline
		pc.Intent = intent
	}
}

// awaitConsent blocks until the human's decision arrives on done, the request context is
// cancelled, or wait elapses. ok=false means no decision (timeout/cancel) — the caller falls
// back to today's "dialog shown, wait" answer.
func awaitConsent(ctx context.Context, done <-chan consentOutcome, wait time.Duration) (consentOutcome, bool) {
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case o := <-done:
		return o, true
	case <-ctx.Done():
		return consentOutcome{}, false
	case <-t.C:
		return consentOutcome{}, false
	}
}

// consume redeems a nonce exactly once: unknown, expired, and already-used ids all fail, and
// a successful consume marks the record used atomically so a concurrent replay loses.
// Redemption is additionally bound to the record: the caller must present the _meta-only
// widget token AND be the same connection and principal that opened the request. Binding
// checks run BEFORE the nonce is burned, so a forged submission (the model guessing, another
// connection replaying a leaked id) cannot deny service to the real widget still waiting on
// the user — and the 128-bit token makes online guessing infeasible anyway.
func (p *pendingStore) consume(id, widgetToken, connID, principal string) (pendingConsent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc, ok := p.m[id]
	if !ok {
		return pendingConsent{}, fmt.Errorf("unknown consent request %q — only ids issued by this gateway can be redeemed", id)
	}
	if pc.used {
		return pendingConsent{}, fmt.Errorf("consent request %q already used — each decision is single-shot", id)
	}
	if p.now() > pc.ExpiresAt {
		delete(p.m, id)
		return pendingConsent{}, fmt.Errorf("consent request %q expired — ask again", id)
	}
	if subtle.ConstantTimeCompare([]byte(widgetToken), []byte(pc.WidgetToken)) != 1 {
		return pendingConsent{}, fmt.Errorf("consent request %q: widget_token mismatch — submission did not come through the widget channel: %w", id, errConsentBinding)
	}
	if connID != pc.ConnID {
		return pendingConsent{}, fmt.Errorf("consent request %q: connection mismatch (submitted on %q, opened on %q): %w", id, connID, pc.ConnID, errConsentBinding)
	}
	if principal != pc.Principal {
		return pendingConsent{}, fmt.Errorf("consent request %q: principal mismatch (submitted as %q, opened by %q): %w", id, principal, pc.Principal, errConsentBinding)
	}
	pc.used = true
	return *pc, nil
}

// listLive returns a copy of every live, unused pending record — the console's read model.
// The web console shows these so a human can GRANT a request from a client (e.g. ChatGPT) that
// can neither elicit nor render the widget. Pruning of the expired happens lazily on create;
// listLive simply skips anything used or past its TTL.
func (p *pendingStore) listLive() []pendingConsent {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var out []pendingConsent
	for _, pc := range p.m {
		if pc.used || now > pc.ExpiresAt {
			continue
		}
		out = append(out, *pc)
	}
	return out
}

// consumeByID redeems a nonce for the CONSOLE path: it burns the record exactly once (unknown,
// expired, already-used, or owner-mismatch all fail) — skipping the widget's widget_token check
// (the console bearer stands in for it) but STILL binding to the record's principal: owner is
// the authenticated console operator, so one operator can never resolve another's pending ask.
// An empty owner means "no owner check" (single-trust-domain callers / tests). The returned
// copy shares the record's done channel, so mintPending's resolve reaches the blocked call.
func (p *pendingStore) consumeByID(id, owner string) (pendingConsent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc, ok := p.m[id]
	if !ok {
		return pendingConsent{}, fmt.Errorf("unknown consent request %q", id)
	}
	if owner != "" && pc.Principal != owner {
		// Do NOT reveal that the id exists under another owner — same error as unknown.
		return pendingConsent{}, fmt.Errorf("unknown consent request %q", id)
	}
	if pc.used {
		return pendingConsent{}, fmt.Errorf("consent request %q already used", id)
	}
	if p.now() > pc.ExpiresAt {
		delete(p.m, id)
		return pendingConsent{}, fmt.Errorf("consent request %q expired", id)
	}
	pc.used = true
	return *pc, nil
}

// sameScopeSet reports whether a and b contain the same scopes regardless of order (and of
// duplicates — scope lists are sets).
func sameScopeSet(a, b []string) bool {
	as, bs := map[string]bool{}, map[string]bool{}
	for _, s := range a {
		as[s] = true
	}
	for _, s := range b {
		bs[s] = true
	}
	if len(as) != len(bs) {
		return false
	}
	for s := range as {
		if !bs[s] {
			return false
		}
	}
	return true
}

// latestForConn returns the newest live, unused pending request opened by this connection —
// the token-recovery path for hosts (Claude Desktop) that strip _meta from tool-result
// notifications: the WIDGET can fetch the token via a bridged resources/read (a channel the
// model has no access to on such hosts), keyed purely by its own connection.
func (p *pendingStore) latestForConn(connID string) (pendingConsent, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *pendingConsent
	for _, pc := range p.m {
		if pc.ConnID != connID || pc.used || pc.ExpiresAt <= p.now() {
			continue
		}
		if best == nil || pc.ExpiresAt > best.ExpiresAt {
			best = pc
		}
	}
	if best == nil {
		return pendingConsent{}, false
	}
	return *best, true
}
