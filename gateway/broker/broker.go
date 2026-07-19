// Package broker is Delegent's stateful session orchestrator. It moves authority: open (mint from the human), narrow (attenuate for a
// sub-agent), escalate (bubble a request up the chain), approve (an ancestor's deliberate
// hand-down), and charge (an atomic debit against a session's budget).
//
// All session and escalation state persists through a store.Store, so a restart or a
// reconnecting agent rehydrates its still-valid grants instead of re-consenting. A session's
// slip chain is stored as the EXACT signed canonical bytes of every link; on load each is
// verified, so a tampered row fails exactly like a tampered wire slip. The holder's private
// key (needed to sign child slips when narrowing/escalating) is sealed at rest via
// keyring.Sealer and unsealed only when a signature is actually required.
//
// Authority is only ever subdivided, never created: every narrow/escalate goes through
// core.Narrow, which folds by intersection, so an ancestor that lacks a scope cannot grant it.
package broker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	core "delegent.dev/protocol"
	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// Broker holds no session state of its own — it reads and writes through the Store.
type Broker struct {
	cp     *controlplane.ControlPlane
	st     store.Store
	sealer keyring.Sealer
	now    func() int64
	rand   func() string
}

// New builds a Broker over the given Store and Sealer. Passing a nil sealer falls back to the
// env-configured one (dev key when DELEGENT_MASTER_KEY is unset).
func New(cp *controlplane.ControlPlane, st store.Store, sealer keyring.Sealer, now func() int64, rand func() string) *Broker {
	if sealer == nil {
		sealer, _ = keyring.FromEnv()
	}
	return &Broker{cp: cp, st: st, sealer: sealer, now: now, rand: rand}
}

func bg() context.Context { return context.Background() }

// Open mints a fresh root session from the principal's own entitlements.
func (b *Broker) Open(principal string, scopes []string, reason string, consent controlplane.Consent) (handle, message string, granted bool) {
	return b.Grant(principal, "", scopes, reason, consent)
}

// Grant is request_access. With an empty handle it opens a NEW session (the human sets the
// TTL and budget). With an existing handle it AUGMENTS that session: it prompts only for the
// scopes not already held, re-mints the slip bound to the SAME key with the union, and keeps
// the original expiry, budget ledger, and holder key — so extending scope never resets the
// clock or the remaining budget, and scopes already held need no prompt at all.
func (b *Broker) Grant(principal, handle string, requested []string, reason string, consent controlplane.Consent) (outHandle, message string, granted bool) {
	if handle == "" {
		pub, priv, err := core.NewKeypair()
		if err != nil {
			return "", "keygen failed", false
		}
		gr, ttl, budget, deny := b.cp.Decide(principal, requested, reason, consent)
		if len(gr) == 0 {
			return "", deny, false
		}
		chain, eff, err := b.cp.MintFor(principal, pub, gr, b.now()+int64(ttl)*60_000, budget)
		if err != nil {
			return "", err.Error(), false
		}
		h := id.New("sess")
		if err := b.persistNew(h, "", principal, chain, priv, pub); err != nil {
			return "", "persist failed: " + err.Error(), false
		}
		return h, "Access granted to " + b.AgentDisplayName(h) + ". effects [" + core.EffectNames(eff) + "] (" + strings.Join(gr, ", ") + ") session: " + h, true
	}

	ss, err := b.st.GetSession(bg(), handle)
	if err != nil {
		return "", "unknown session " + handle, false
	}
	chain, err := b.rowsToChain(ss.Chain)
	if err != nil {
		return "", "session unreadable: " + err.Error(), false
	}
	cur := core.Fold(chain, nil)
	var newReq []string
	for _, sc := range requested {
		if !contains(cur.Scopes, sc) {
			newReq = append(newReq, sc)
		}
	}
	if len(newReq) == 0 {
		return handle, "Session " + handle + " already holds " + strings.Join(requested, ", ") + " — nothing to add.", true
	}
	// augmenting mints on the session's OWN principal (the issuer that opened it)
	gr, _, _, deny := b.cp.Decide(ss.Principal, newReq, reason, consent) // prompt only for the new scopes; ttl/budget preserved
	if len(gr) == 0 {
		return handle, deny, false
	}
	all := union(cur.Scopes, gr)
	newChain, eff, err := b.cp.MintFor(ss.Principal, ss.Pubkey, all, cur.Exp, cur.Budget) // same key, SAME expiry + budget
	if err != nil {
		return handle, err.Error(), false
	}
	// Preserve everything but the chain and its folded projection — the budget ledger and the
	// original expiry are untouched, so augmenting never resets the clock or the spend counter.
	ss.Chain = b.chainToRows(newChain)
	f := core.Fold(newChain, nil)
	ss.Effects, ss.Scopes, ss.Ceiling = uint(f.Effects), f.Scopes, f.Ceiling
	if err := b.st.PutSession(bg(), ss); err != nil {
		return handle, "persist failed: " + err.Error(), false
	}
	return handle, "Access extended on " + handle + " (" + b.AgentDisplayName(handle) + ") — now holds effects [" + core.EffectNames(eff) + "] (" + strings.Join(all, ", ") + "), same expiry.", true
}

// maxNameDepth caps how many ancestors AgentDisplayName walks — a runaway (or adversarially
// deep) chain never turns a log line into an unbounded store scan.
const maxNameDepth = 5

// AgentDisplayName derives a stable, human-readable identity for a session from its handle:
// "main-agent-<last 8 chars>" for a root session, and for children the whole parent chain
// rendered root-first, e.g. "main-agent-1a2b3c4d→sub-agent-5e6f7a8b". An empty handle (a
// connection that has not consented yet) reads as "new agent connection"; any unresolvable
// handle (missing session, missing ancestor) falls back to the bare handle. Chains deeper
// than maxNameDepth are truncated with a leading "…→".
func (b *Broker) AgentDisplayName(handle string) string {
	if handle == "" {
		return "new agent connection"
	}
	// Walk leaf → root, collecting handles.
	var lineage []string // lineage[0] is the leaf (handle itself)
	truncated := false
	for cur := handle; cur != ""; {
		if len(lineage) == maxNameDepth {
			truncated = true
			break
		}
		ss, err := b.st.GetSession(bg(), cur)
		if err != nil {
			return handle // graceful fallback: an unresolvable link names nothing
		}
		lineage = append(lineage, cur)
		cur = ss.ParentHandle
	}
	parts := make([]string, len(lineage))
	for i, h := range lineage {
		role := "sub-agent"
		if i == len(lineage)-1 && !truncated { // the root-most link actually reached the root
			role = "main-agent"
		}
		parts[len(lineage)-1-i] = role + "-" + last8(h)
	}
	name := strings.Join(parts, "→")
	if truncated {
		name = "…→" + name
	}
	return name
}

// last8 is the short display suffix of a handle — enough to tell sessions apart at a glance.
func last8(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[len(h)-8:]
}

// sessionLive reports whether a session still confers authority: not revoked and not past its
// expiry (0 = never expires). The single predicate the authorize gate and any revoker share.
func (b *Broker) sessionLive(ss *store.Session) bool {
	if ss.RevokedAt != 0 {
		return false
	}
	if ss.ExpiresAt != 0 && b.now() >= ss.ExpiresAt {
		return false
	}
	return true
}

// RevokeSelf revokes the session bound to handle and, when chain is set, every descendant
// session it (transitively) minted — a connection dropping its own authority. Returns the
// number of sessions revoked. Unknown/already-revoked handles are a no-op (count reflects only
// what this call flipped). Callers must have verified the handle belongs to the caller.
func (b *Broker) RevokeSelf(handle string, chain bool) int {
	revoked := 0
	seen := map[string]bool{}
	var walk func(h string)
	walk = func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		ss, err := b.st.GetSession(bg(), h)
		if err != nil {
			return
		}
		if ss.RevokedAt == 0 {
			ss.RevokedAt = b.now()
			if err := b.st.PutSession(bg(), ss); err == nil {
				revoked++
			}
		}
		if !chain {
			return
		}
		// Find children: sessions whose ParentHandle is h, among this principal's sessions.
		kids, err := b.st.ListSessions(bg(), ss.Principal)
		if err != nil {
			return
		}
		for _, k := range kids {
			if k.ParentHandle == h {
				walk(k.Handle)
			}
		}
	}
	walk(handle)
	return revoked
}

// LatestLiveSession returns the handle of a principal's most-recently-created session that is
// still live (unexpired, unrevoked), or "" if none. It is how a reconnecting agent — or a
// fresh connection after a gateway restart — resumes its grants from the store instead of
// re-consenting. (Single-principal today; multi-agent disambiguation, where the agent presents
// its own handle, is the next increment.)
func (b *Broker) LatestLiveSession(principal string) string {
	sessions, err := b.st.ListSessions(bg(), principal)
	if err != nil {
		return ""
	}
	now := b.now()
	best := ""
	var bestCreated int64 = -1
	for _, s := range sessions {
		if s.ExpiresAt > now && s.CreatedAt > bestCreated {
			best, bestCreated = s.Handle, s.CreatedAt
		}
	}
	return best
}

// LiveScopes returns the scopes a session currently confers, or nil if the handle is unknown or
// the session is no longer live (revoked or expired). It shares the exact liveness predicate —
// and injected clock — of the authorize gate, so "held" here means the same thing it does there.
func (b *Broker) LiveScopes(handle string) []string {
	if handle == "" {
		return nil
	}
	ss, err := b.st.GetSession(bg(), handle)
	if err != nil || ss == nil || !b.sessionLive(ss) {
		return nil
	}
	return ss.Scopes
}

// SessionLive reports whether the session bound to handle still confers authority (exists, not
// revoked, not expired). The gateway uses it to drop a stale connection binding so re-consent
// mints a FRESH session instead of augmenting a dead one.
func (b *Broker) SessionLive(handle string) bool {
	if handle == "" {
		return false
	}
	ss, err := b.st.GetSession(bg(), handle)
	return err == nil && ss != nil && b.sessionLive(ss)
}

// Authorize resolves a session and decides a classified request against its effective slip —
// the check the vendor-tool proxy makes before forwarding.
func (b *Broker) Authorize(handle string, req core.Request) (core.Classified, core.Decision, bool) {
	ss, err := b.st.GetSession(bg(), handle)
	if err != nil {
		return core.Classified{}, core.Decision{}, false
	}
	// A revoked or expired session holds no authority — the gate must reject it, not just the
	// listing. Without this, revocation (console or the revoke tool) is cosmetic: a live
	// connection keeps folding a dead session's slips.
	if !b.sessionLive(ss) {
		return core.Classified{}, core.Decision{}, false
	}
	chain, err := b.rowsToChain(ss.Chain)
	if err != nil {
		return core.Classified{}, core.Decision{}, false
	}
	eff := core.Fold(chain, nil)
	c := core.Classify(b.cp.Adapter(), req)
	return c, core.Authorize(eff, c), true
}

// Charge atomically debits a session's budget for a spending call. Returns ok=false (with a
// message) when the session has no budget headroom left — the enforcement that makes a budget
// ceiling real under concurrent agents. A session with no configured budget is never charged.
func (b *Broker) Charge(handle string, amountUSD float64, tool string) (ok bool, message string) {
	if amountUSD <= 0 {
		return true, ""
	}
	cents := usdToCents(amountUSD)
	remaining, err := b.st.Spend(bg(), handle, cents, store.LedgerEntry{Amount: cents, Tool: tool})
	if err == store.ErrInsufficientBudget {
		return false, fmt.Sprintf("budget exceeded: %s left, %s requested", centsUSD(remaining), centsUSD(cents))
	}
	if err != nil {
		return false, "budget check failed: " + err.Error()
	}
	return true, "charged " + centsUSD(cents) + " (" + centsUSD(remaining) + " left)"
}

// NarrowOpts are the attenuations a narrow_access may request. Nil/zero means "inherit".
type NarrowOpts struct {
	Effects []string
	Scopes  []string
	Ceiling []string
	Budget  *float64
	Minutes *int
}

// Narrow mints a strictly-weaker child session for a sub-agent. Offline, no human.
func (b *Broker) Narrow(handle string, opts NarrowOpts) (childHandle, message string, ok bool) {
	ss, err := b.st.GetSession(bg(), handle)
	if err != nil {
		return "", "unknown session", false
	}
	chain, err := b.rowsToChain(ss.Chain)
	if err != nil {
		return "", "session unreadable: " + err.Error(), false
	}
	signer, err := b.signerOf(ss)
	if err != nil {
		return "", "session key unavailable: " + err.Error(), false
	}

	cav := core.Caveats{}
	if opts.Effects != nil {
		e := effectsOf(opts.Effects)
		cav.Effects = &e
	}
	if opts.Scopes != nil {
		cav.Scopes = &opts.Scopes
	}
	if opts.Ceiling != nil {
		cav.Ceiling = &opts.Ceiling
	}
	cav.Budget = opts.Budget
	if opts.Minutes != nil {
		exp := b.now() + int64(*opts.Minutes)*60_000
		cav.Exp = &exp
	}

	childPub, childPriv, _ := core.NewKeypair()
	childChain, _, err := core.Narrow(chain, cav, childPub, signer, b.rand())
	if err != nil {
		return "", err.Error(), false
	}
	ch := id.New("sess")
	if err := b.persistNew(ch, handle, ss.Principal, childChain, childPriv, childPub); err != nil {
		return "", "persist failed: " + err.Error(), false
	}
	e := core.Fold(childChain, nil)
	// The chain name makes the sub-agent's identity visible in the transcript: whoever reads
	// the narrow_access result sees WHO the child is, not just its handle.
	return ch, "Narrowed. session: " + ch + " (" + b.AgentDisplayName(ch) + ") effects [" + core.EffectNames(e.Effects) + "] scopes [" + strings.Join(e.Scopes, ", ") + "] depth " + strconv.Itoa(e.Depth), true
}

// Escalate bubbles a scope request UP the delegation chain to the nearest ancestor that HOLDS
// it. If the requester's ceiling pre-authorised the scope, it is minted immediately (a
// decision the issuer already took at spawn time). Otherwise it parks as PENDING — nothing is
// minted until that ancestor approves. If no ancestor holds it, the human at the root is asked.
func (b *Broker) Escalate(handle string, scopes []string, reason string, consent controlplane.Consent) (message string, granted bool) {
	ss, err := b.st.GetSession(bg(), handle)
	if err != nil {
		return "unknown session", false
	}
	chain, err := b.rowsToChain(ss.Chain)
	if err != nil {
		return "session unreadable: " + err.Error(), false
	}
	preAuth := core.Fold(chain, nil).Ceiling
	autoOK := subset(scopes, preAuth)

	for cur := ss.ParentHandle; cur != ""; {
		anc, err := b.st.GetSession(bg(), cur)
		if err != nil {
			break
		}
		ancChain, err := b.rowsToChain(anc.Chain)
		if err != nil {
			break
		}
		if subset(scopes, core.Fold(ancChain, nil).Scopes) {
			if autoOK {
				ch, msg, ok := b.mintFrom(cur, handle, scopes)
				if !ok {
					return msg, false
				}
				return "Escalated to " + cur + ", which holds and pre-authorised " + strings.Join(scopes, ", ") + " — granted immediately, no approval. " + ch + " " + msg, true
			}
			escID := id.New("esc")
			esc := &store.Escalation{ID: escID, ChildHandle: handle, ParentHandle: cur, Scopes: scopes, Reason: reason, Status: "pending", CreatedAt: b.now()}
			if err := b.st.PutEscalation(bg(), esc); err != nil {
				return "persist failed: " + err.Error(), false
			}
			// Do NOT hand the child its ancestor's handle: handle possession is authority, and
			// disclosing it here would let the escalating agent approve its own request.
			return "Escalation " + escID + " PENDING, addressed to " + b.AgentDisplayName(cur) + " — that agent must call approve_escalation with its OWN session and id " + escID + ". Nothing minted yet.", false
		}
		cur = anc.ParentHandle
	}

	// Ran out of chain — only the human at the root can grant it now.
	_, msg, ok := b.Open(ss.Principal, scopes, reason, consent)
	if ok {
		return "No ancestor held " + strings.Join(scopes, ", ") + " — escalated to the human. " + msg, true
	}
	return "No ancestor held " + strings.Join(scopes, ", ") + " — escalated to the human. " + msg, false
}

// ApproveEscalation is the ancestor's deliberate hand-down: only the session that was asked
// may approve, and it can only mint what it holds (a narrow, every clamp applies).
func (b *Broker) ApproveEscalation(ancestorHandle, id string) (message string, ok bool) {
	req, err := b.st.GetEscalation(bg(), id)
	if err != nil || req.Status != "pending" {
		return "unknown or already-resolved escalation '" + id + "'", false
	}
	if req.ParentHandle != ancestorHandle {
		return "escalation " + id + " was addressed to " + req.ParentHandle + ", not " + ancestorHandle, false
	}
	ch, msg, minted := b.mintFrom(ancestorHandle, req.ChildHandle, req.Scopes)
	if !minted {
		return msg, false
	}
	req.Status = "approved"
	req.ResolvedAt = b.now()
	_ = b.st.PutEscalation(bg(), req)
	return "Escalation " + id + " APPROVED by " + ancestorHandle + ". " + ch + " " + msg + " No human was asked.", true
}

// PendingEscalations lists requests awaiting THIS session's approval.
func (b *Broker) PendingEscalations(ancestorHandle string) []store.Escalation {
	es, err := b.st.ListPendingEscalations(bg(), ancestorHandle)
	if err != nil {
		return nil
	}
	out := make([]store.Escalation, len(es))
	for i, e := range es {
		out[i] = *e
	}
	return out
}

// mintFrom hands a slip DOWN from an ancestor to a requester — the one place authority moves
// downward, used by both the pre-authorised and approved paths. Depth is never regained and
// the ceiling never grows.
func (b *Broker) mintFrom(ancestorHandle, requesterHandle string, scopes []string) (childHandle, message string, ok bool) {
	anc, err := b.st.GetSession(bg(), ancestorHandle)
	if err != nil {
		return "", "session gone", false
	}
	req, err := b.st.GetSession(bg(), requesterHandle)
	if err != nil {
		return "", "session gone", false
	}
	ancChain, err := b.rowsToChain(anc.Chain)
	if err != nil {
		return "", "ancestor unreadable: " + err.Error(), false
	}
	reqChain, err := b.rowsToChain(req.Chain)
	if err != nil {
		return "", "requester unreadable: " + err.Error(), false
	}
	ancSigner, err := b.signerOf(anc)
	if err != nil {
		return "", "ancestor key unavailable: " + err.Error(), false
	}

	r := core.Fold(reqChain, nil)
	want := union(r.Scopes, scopes)
	eff, _ := b.cp.PowerOf(want)

	depth := r.Depth
	ceiling := r.Ceiling
	cav := core.Caveats{Scopes: &want, Effects: &eff, Ceiling: &ceiling, Depth: &depth}
	childPub, childPriv, _ := core.NewKeypair()
	childChain, _, err := core.Narrow(ancChain, cav, childPub, ancSigner, b.rand())
	if err != nil {
		return "", err.Error(), false
	}
	ch := id.New("sess")
	if err := b.persistNew(ch, ancestorHandle, anc.Principal, childChain, childPriv, childPub); err != nil {
		return "", "persist failed: " + err.Error(), false
	}
	e := core.Fold(childChain, nil)
	return "session: " + ch + " (" + b.AgentDisplayName(ch) + ")", "effects [" + core.EffectNames(e.Effects) + "] (" + strings.Join(e.Scopes, ", ") + ") depth " + strconv.Itoa(e.Depth), true
}

// --- persistence helpers ---

// persistNew writes a brand-new session: chain as canonical rows, holder key sealed, budget
// ledger initialised from the slip's budget. Used by open, narrow, and hand-down mints.
func (b *Broker) persistNew(handle, parent, principal string, chain core.Chain, priv ed25519.PrivateKey, pub string) error {
	sealed, err := b.sealer.Seal(priv)
	if err != nil {
		return err
	}
	f := core.Fold(chain, nil)
	ss := &store.Session{
		Handle: handle, Principal: principal, ParentHandle: parent,
		Chain: b.chainToRows(chain), SealedKey: sealed, Pubkey: pub,
		Effects: uint(f.Effects), Scopes: f.Scopes, Ceiling: f.Ceiling,
		ExpiresAt: f.Exp, CreatedAt: b.now(),
	}
	if f.Budget > 0 {
		ss.HasBudget = true
		ss.BudgetTotalC = usdToCents(f.Budget)
		ss.BudgetRemainingC = usdToCents(f.Budget)
	}
	return b.st.PutSession(bg(), ss)
}

// chainToRows projects a chain to the exact signed bytes of each slip (core.Canonical is what
// SignSlip signed over), preserving byte-for-byte what the signatures cover.
func (b *Broker) chainToRows(chain core.Chain) []store.SlipRow {
	rows := make([]store.SlipRow, len(chain))
	for i, sl := range chain {
		rows[i] = store.SlipRow{Canonical: core.Canonical(sl.Body), Sig: sl.Sig}
	}
	return rows
}

// rowsToChain rebuilds a chain from stored rows, verifying every signature over the stored
// canonical bytes. A tampered or corrupt row is rejected — the same fail-closed check a wire
// slip gets.
func (b *Broker) rowsToChain(rows []store.SlipRow) (core.Chain, error) {
	chain := make(core.Chain, 0, len(rows))
	for i, r := range rows {
		var body core.SlipBody
		if err := json.Unmarshal(r.Canonical, &body); err != nil {
			return nil, fmt.Errorf("slip %d: %w", i, err)
		}
		if !core.VerifyBytes(b.issuerPub(body.Iss), r.Canonical, r.Sig) {
			return nil, fmt.Errorf("bad signature on stored slip %d", i)
		}
		chain = append(chain, core.Slip{Body: body, Sig: r.Sig})
	}
	return chain, nil
}

// issuerPub resolves a slip issuer to its public key: a named principal maps to that
// principal's own root public key; an intermediate link is keyed by its raw hex public key.
func (b *Broker) issuerPub(iss string) string {
	if pub, ok := b.cp.PublicKeyOf(iss); ok {
		return pub
	}
	return iss
}

// signerOf unseals a session's holder private key into a Signer. Called only when a signature
// is actually needed (narrow/escalate hand-down), never on the authorize hot path.
func (b *Broker) signerOf(ss *store.Session) (core.Signer, error) {
	priv, err := b.sealer.Unseal(ss.SealedKey)
	if err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("unsealed key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return core.NewEd25519Signer(ed25519.PrivateKey(priv)), nil
}

// usdToCents converts a USD amount to integer cents (round half away from zero).
func usdToCents(usd float64) int64 {
	if usd >= 0 {
		return int64(usd*100 + 0.5)
	}
	return int64(usd*100 - 0.5)
}

func centsUSD(c int64) string { return "$" + strconv.FormatFloat(float64(c)/100, 'f', 2, 64) }

func effectsOf(names []string) core.Effect {
	var e core.Effect
	for _, n := range names {
		if bit, ok := core.EffectByName(n); ok {
			e |= bit
		}
	}
	return e
}

func subset(a, b []string) bool {
	for _, s := range a {
		if !contains(b, s) {
			return false
		}
	}
	return true
}
func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, s := range b {
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
