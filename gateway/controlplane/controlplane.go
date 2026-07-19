// Package controlplane is Delegent's authority tier, minus its transport. It checks a
// principal's entitlements, detects over-ask from the agent's own stated reason, obtains
// human consent, and mints a signed slip bound to the caller's key — returning the chain
// the gateway proxy verifies. Consent and the signing key are injected, so this logic is
// testable headless today and wires to an MCP surface + KMS later.
//
// Receipts persist through an injected store.Store; the root signing key stays behind the
// core.Signer port (file/env now, KMS later) and never touches the database.
package controlplane

import (
	"context"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"

	core "delegent.dev/protocol"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/loader"
	"delegent.dev/gateway/store"
)

// ConsentScope is one grantable scope presented to the human, with its description.
type ConsentScope struct {
	Scope    string
	Human    string
	Risk     string
	Warnings []string
}

// ConsentRequest is what the human is asked to approve.
type ConsentRequest struct {
	Reason          string
	OverAsk         []string // scopes requested beyond what the stated reason needs
	OverAskWarnings []string
	Ungrantable     []string // scopes the principal does not even hold (shown, never offered)
	Scopes          []ConsentScope
}

// ConsentAnswer is the human's decision.
type ConsentAnswer struct {
	Granted    []string
	TTLMinutes int
	BudgetUSD  float64
}

// Consent obtains a human decision. A headless implementation may auto-answer; the MCP
// transport backs it with elicitation. Returning nil means "declined".
type Consent interface {
	Ask(ConsentRequest) (*ConsentAnswer, error)
}

// RootKeys resolves a principal to its OWN root signing key (Signer, for minting) and public
// key (Public, for verification). Each registered principal signs with its own key — there is
// no shared process-wide root key. A KMS-backed custodian satisfies the same port.
type RootKeys interface {
	Signer(principal string) (core.Signer, error)
	Public(principal string) (string, bool)
}

// Options configures a ControlPlane. RootKeys custodies the per-principal signing keys.
// Store persists receipts. Now/Rand are injected so the logic is deterministic under test.
type Options struct {
	Vendor     string
	Adapter    core.Adapter
	Advisor    loader.Advisor
	Principals map[string][]string
	RootName   string   // the operating principal, e.g. "root:alice"
	RootKeys   RootKeys // per-principal signing keys
	Store      store.Store
	Now        func() int64
	Rand       func() string // nonce source
}

type ControlPlane struct {
	o Options
	// recMu serializes the read-last-hash → hash → sign → append in record, so concurrent
	// decisions for the same principal can't fork that principal's receipt chain.
	recMu sync.Mutex
}

func New(o Options) *ControlPlane {
	if o.RootName == "" {
		o.RootName = "root:alice"
	}
	if o.Store == nil {
		o.Store = store.NewMemStore()
	}
	return &ControlPlane{o: o}
}

// RootName is the operating principal. RootPub is its public key. PublicKeyOf resolves ANY
// principal to its public key — how a verifier turns a slip's named issuer into a key.
func (cp *ControlPlane) RootName() string { return cp.o.RootName }
func (cp *ControlPlane) RootPub() string {
	pub, _ := cp.o.RootKeys.Public(cp.o.RootName)
	return pub
}
func (cp *ControlPlane) PublicKeyOf(principal string) (string, bool) {
	return cp.o.RootKeys.Public(principal)
}
func (cp *ControlPlane) Adapter() core.Adapter { return cp.o.Adapter }

// AllScopes is the scope universe this vendor advertises: the sorted keys of the advisor's
// per-scope descriptions. plan_access asks for all of them, then DescribeConsent filters to
// the grantable subset for the principal. Empty when the target has no advisor.
func (cp *ControlPlane) AllScopes() []string {
	out := make([]string, 0, len(cp.o.Advisor.Scopes))
	for s := range cp.o.Advisor.Scopes {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Receipts returns the persisted audit trail (all principals). Errors read as an empty trail.
func (cp *ControlPlane) Receipts() []store.Receipt {
	rs, err := cp.o.Store.ListReceipts(context.Background(), store.ReceiptFilter{})
	if err != nil {
		return nil
	}
	out := make([]store.Receipt, len(rs))
	for i, r := range rs {
		out[i] = *r
	}
	return out
}

// Result is what request_access returns. On success Chain is the signed slip to hand to
// the proxy; the caller already holds the matching private key.
type Result struct {
	Granted bool
	Chain   core.Chain
	Effects core.Effect
	Scopes  []string
	Message string
}

// RequestAccess is the top of the chain: a grant is a narrowing of the principal's own
// entitlements, exactly as a child slip narrows its parent. It runs Decide (entitlement +
// over-ask + consent) then MintFor with a fresh TTL. Session AUGMENTATION uses the same two
// pieces but preserves the existing expiry — see the broker.
func (cp *ControlPlane) RequestAccess(principal string, requested []string, reason, callerPub string, consent Consent) Result {
	granted, ttl, budget, denyMsg := cp.Decide(principal, requested, reason, consent)
	if len(granted) == 0 {
		return Result{Granted: false, Message: denyMsg}
	}
	chain, effects, err := cp.MintFor(principal, callerPub, granted, cp.now()+int64(ttl)*60_000, budget)
	if err != nil {
		return Result{Granted: false, Message: "mint failed: " + err.Error()}
	}
	return Result{
		Granted: true, Chain: chain, Effects: effects, Scopes: granted,
		Message: "Access granted. effects [" + core.EffectNames(effects) + "] (" + strings.Join(granted, ", ") + ")",
	}
}

// DescribeConsent assembles exactly what a consent dialog would show for this ask — over-ask
// detection from the agent's own stated reason, entitlement filtering (a principal is never
// offered authority it does not hold), and the advisor's per-scope human text — WITHOUT
// consulting a human, minting anything, or writing a receipt. Decide uses it as its first
// phase; the MCP Apps widget flow uses it to build the pending-consent payload the widget
// renders before any decision exists.
func (cp *ControlPlane) DescribeConsent(principal string, requested []string, reason string) ConsentRequest {
	needed := cp.requiredScopes(reason)
	var overAsk, overAskWarnings []string
	for _, s := range requested {
		if !contains(needed, s) {
			overAsk = append(overAsk, s)
			overAskWarnings = append(overAskWarnings, "⚠️ Requesting '"+s+"', but the stated task only requires: "+strings.Join(needed, ", ")+".")
		}
	}
	held := cp.o.Principals[principal]
	var ungrantable []string
	var scopes []ConsentScope
	for _, s := range requested {
		if contains(held, s) {
			info := cp.o.Advisor.Scopes[s]
			scopes = append(scopes, ConsentScope{Scope: s, Human: info.Human, Risk: info.Risk, Warnings: info.Warnings})
		} else {
			ungrantable = append(ungrantable, s)
		}
	}
	return ConsentRequest{Reason: reason, OverAsk: overAsk, OverAskWarnings: overAskWarnings, Ungrantable: ungrantable, Scopes: scopes}
}

// Decide runs the entitlement check, over-ask detection (from the agent's OWN reason, so it
// fires even when the agent skips plan_access), and consent — but mints NOTHING. Returns
// the granted scopes (empty => denied, with denyMsg) plus the human's ttl/budget answer.
// Splitting decide from mint is what lets a session be augmented with new scopes while
// keeping its original expiry.
func (cp *ControlPlane) Decide(principal string, requested []string, reason string, consent Consent) (granted []string, ttlMinutes int, budgetUSD float64, denyMsg string) {
	cr := cp.DescribeConsent(principal, requested, reason)
	if len(cr.Scopes) == 0 {
		msg := "Nothing granted. " + principal + " does not hold: " + strings.Join(cr.Ungrantable, ", ") +
			" — outside its own entitlements, so no consent dialog can grant it."
		cp.record(store.Receipt{Principal: principal, Tool: "request_access", Scopes: requested, Decision: "deny", Reason: msg, CreatedAt: cp.now()})
		return nil, 0, 0, msg
	}
	grantable := make([]string, len(cr.Scopes))
	for i, sc := range cr.Scopes {
		grantable[i] = sc.Scope
	}
	answer, err := consent.Ask(cr)
	if err != nil || answer == nil {
		msg := "Declined. No slip minted."
		cp.record(store.Receipt{Principal: principal, Tool: "request_access", Scopes: requested, Decision: "deny", Reason: msg, CreatedAt: cp.now()})
		return nil, 0, 0, msg
	}
	for _, s := range answer.Granted {
		if contains(grantable, s) {
			granted = append(granted, s)
		}
	}
	if len(granted) == 0 {
		msg := "Declined. No slip minted."
		cp.record(store.Receipt{Principal: principal, Tool: "request_access", Scopes: requested, Decision: "deny", Reason: msg, CreatedAt: cp.now()})
		return nil, 0, 0, msg
	}
	return granted, answer.TTLMinutes, answer.BudgetUSD, ""
}

// MintFor mints a root slip binding the granted scopes to callerPub, with an explicit
// expiry and budget. A new session passes exp = now + ttl; augmenting an existing session
// passes its ORIGINAL exp, so extending scope never resets the clock. Records a grant
// receipt.
func (cp *ControlPlane) MintFor(principal, callerPub string, granted []string, exp int64, budget float64) (core.Chain, core.Effect, error) {
	effects, methods := cp.powerOf(granted)
	body := core.SlipBody{
		V: 1, Iss: principal, Aud: callerPub, Vendor: cp.o.Vendor,
		Effects: effects, Methods: methods,
		Scopes:    granted,
		Ceiling:   granted, // the root's ceiling IS its grant: no auto-pulling more from the human
		Resources: []string{""},
		Budget:    budget,
		Exp:       exp,
		Depth:     2,
		Nonce:     cp.nonce(),
	}
	signer, err := cp.o.RootKeys.Signer(principal)
	if err != nil {
		return nil, 0, err
	}
	slip, err := core.SignSlip(body, signer)
	if err != nil {
		return nil, 0, err
	}
	cp.record(store.Receipt{Principal: principal, Tool: "request_access", Scopes: granted, Effect: core.EffectNames(effects), Decision: "grant", Reason: "ok", CreatedAt: cp.now()})
	return core.Chain{slip}, effects, nil
}

// requiredScopes maps a plain-language reason to the minimal scopes, via the advisor's
// intent hints (adapter DATA, not engine code). Deterministic: hints are tried in sorted
// key order; if none match, needed is empty and every requested scope reads as over-ask.
func (cp *ControlPlane) requiredScopes(reason string) []string {
	lower := strings.ToLower(reason)
	seen := map[string]bool{}
	var needed []string
	keys := make([]string, 0, len(cp.o.Advisor.IntentHints))
	for k := range cp.o.Advisor.IntentHints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, phrases := range keys {
		if strings.HasPrefix(phrases, "_") {
			continue
		}
		if re, err := regexp.Compile(phrases); err == nil && re.MatchString(lower) {
			for _, s := range cp.o.Advisor.IntentHints[phrases] {
				if !seen[s] {
					seen[s] = true
					needed = append(needed, s)
				}
			}
		}
	}
	return needed
}

// PowerOf is the exported form of powerOf, used by the broker when escalation recomputes
// the effects a widened scope set confers.
func (cp *ControlPlane) PowerOf(granted []string) (core.Effect, core.Method) {
	return cp.powerOf(granted)
}

// powerOf derives the effect/method bits a set of granted scopes confers, by unioning
// every adapter rule whose required scopes are all held. Effects follow from scopes, so
// the slip's power is computed, never asserted.
func (cp *ControlPlane) powerOf(granted []string) (core.Effect, core.Method) {
	var eff core.Effect
	var meth core.Method
	for _, r := range cp.o.Adapter.Classify {
		if r.Match == nil || !subset(r.Scopes, granted) {
			continue
		}
		if e, ok := core.EffectByName(r.Effect); ok {
			eff |= e
		}
		name := r.Method
		if name == nil {
			name = r.Match.Method
		}
		if name != nil {
			if m, ok := core.MethodByName(*name); ok {
				meth |= m
			}
		}
	}
	return eff, meth
}

// record is the single choke point that mints every receipt. It stamps an id/timestamp, links
// the receipt into its principal's tamper-evident chain (PrevHash → Hash), and signs the Hash
// with the principal's root key. Signing is fail-soft: an unavailable key records the receipt
// UNSIGNED with a warning rather than breaking the decision path over an audit-signing failure.
func (cp *ControlPlane) record(r store.Receipt) {
	ctx := context.Background()
	if r.ID == "" {
		r.ID = id.New("rcpt")
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = cp.now()
	}

	cp.recMu.Lock()
	defer cp.recMu.Unlock()

	prev, err := cp.o.Store.LastReceiptHash(ctx, r.Principal)
	if err != nil {
		log.Printf("⚠️ receipt %s: last-hash lookup for %q failed (%v) — restarting chain", r.ID, r.Principal, err)
		prev = ""
	}
	r.PrevHash = prev
	r.Hash = receiptHash(&r, prev)

	if sg, err := cp.o.RootKeys.Signer(r.Principal); err == nil {
		if s, err := sg.Sign([]byte(r.Hash)); err == nil {
			r.Sig = s
		} else {
			log.Printf("⚠️ receipt %s: signing failed for %q (%v) — recorded unsigned", r.ID, r.Principal, err)
		}
	} else {
		log.Printf("⚠️ receipt %s: no signer for %q (%v) — recorded unsigned", r.ID, r.Principal, err)
	}

	_ = cp.o.Store.AppendReceipt(ctx, &r)
}
func (cp *ControlPlane) now() int64 {
	if cp.o.Now != nil {
		return cp.o.Now()
	}
	return 0
}
func (cp *ControlPlane) nonce() string {
	if cp.o.Rand != nil {
		return cp.o.Rand()
	}
	return "nonce"
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func subset(a, b []string) bool {
	for _, s := range a {
		if !contains(b, s) {
			return false
		}
	}
	return true
}
