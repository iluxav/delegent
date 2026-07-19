package gateway

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// instance is what the Registry caches per target: the Gateway's HTTP surface and teardown,
// plus the console-consent read/resolve surface the API reaches through the Registry.
// (An interface so tests can substitute a fake builder.)
type instance interface {
	Handler() http.Handler
	Close()
	// PendingViews returns this target's live, unused pending consents for owner (empty = all).
	PendingViews(owner string) []PendingView
	// ResolvePending applies a human console decision to a pending id held by THIS gateway.
	// ok=false when the id is not this gateway's (unknown/expired/used) — the Registry tries
	// each gateway until one owns it.
	ResolvePending(id string, d consoleDecision) (ok, granted bool, message string)
}

// errDisabled marks a target that exists but is switched off in the console.
var errDisabled = errors.New("target disabled")

// Registry serves /mcp/{target}: it lazily builds ONE Gateway per target id on first request,
// caches it, and routes subsequent requests to it. Builds are single-flight per target (a
// slow upstream connect never stampedes), and a FAILED build is not cached — the next request
// retries. Invalidate(targetID) closes and drops a cached instance so console changes
// (enable/disable, credential replacement) take effect live, without a restart.
type Registry struct {
	st     store.Store
	sealer keyring.Sealer

	// build constructs the per-target instance; swapped in tests.
	build func(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (instance, error)

	// hub fans console park/resolve events out to the API's SSE subscribers. Gateways publish
	// to it (wired in build); it is process-wide (one Registry per process).
	hub *ConsentHub

	// notifier alerts owners out-of-band (telegram, …) when a consent request parks; wired
	// into every built gateway. nil = no notification.
	notifier ConsentNotifier

	mu    sync.Mutex
	slots map[string]*slot
	// aggregates caches the per-user /mcp aggregate; dropped wholesale on any Invalidate,
	// since an aggregate's tool list mirrors the target set.
	aggregates map[string]*Aggregate
}

// slot serializes build/serve/invalidate for one target id (single-flight).
type slot struct {
	mu sync.Mutex
	gw instance
}

// ConsentNotifier alerts a request's owner on an out-of-band channel (telegram, …) when a
// console consent request is parked. Implementations are advisory: they may notify, never
// decide. Satisfied by telegram.Notifier.
type ConsentNotifier interface {
	ConsentParked(r *store.ConsentRequest)
}

// SetNotifier wires the out-of-band consent notifier into every gateway this registry builds
// (and future rebuilds). Call before traffic; nil disables notification.
func (r *Registry) SetNotifier(n ConsentNotifier) { r.notifier = n }

// NewRegistry builds a Registry over the shared store and sealer.
func NewRegistry(st store.Store, sealer keyring.Sealer) *Registry {
	hub := newConsentHub()
	r := &Registry{
		st:         st,
		sealer:     sealer,
		hub:        hub,
		slots:      map[string]*slot{},
		aggregates: map[string]*Aggregate{},
	}
	r.build = func(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (instance, error) {
		g, err := New(ctx, st, sealer, target)
		if err != nil {
			return nil, err
		}
		g.hub = hub // console park/resolve events flow to the API's SSE stream
		g.notifier = r.notifier
		return g, nil
	}
	go r.expireLoop()
	return r
}

// expireLoop sweeps stale pending consent requests every 60s: any pending row past its TTL is
// flipped to "expired" in the store, and a `resolved` event is published so open consoles drop it.
// Runs for the process lifetime (the Registry is process-wide). No-op when no store is wired.
func (r *Registry) expireLoop() {
	if r.st == nil {
		return
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		ctx := context.Background()
		before, err := r.st.ListConsentRequests(ctx, "", false)
		if err != nil {
			log.Printf("[delegent] consent expiry sweep: list failed: %v", err)
			continue
		}
		now := nowMillis()
		n, err := r.st.ExpireStaleConsentRequests(ctx, now)
		if err != nil {
			log.Printf("[delegent] consent expiry sweep: %v", err)
			continue
		}
		if n > 0 {
			// Publish a resolved event for each id that just expired so consoles drop it live.
			for _, cr := range before {
				if cr.ExpiresAt != 0 && now > cr.ExpiresAt {
					r.hub.publish(ConsentEvent{Type: "resolved", Owner: cr.Principal, ID: cr.ID})
				}
			}
			log.Printf("[delegent] consent expiry sweep: expired %d stale pending request(s)", n)
		}
		// Also reap abandoned target-less OAuth pending rows (and their sealed token/secret
		// blobs) older than 1h, so a wizard the operator never finished leaves no orphaned live
		// vendor token behind. created_at is unix SECONDS here (oauth_pending), unlike the ms
		// consent timestamps above.
		if reaped, err := r.st.ExpireStalePending(ctx, time.Now().Add(-time.Hour).Unix()); err != nil {
			log.Printf("[delegent] oauth pending sweep: %v", err)
		} else if reaped > 0 {
			log.Printf("[delegent] oauth pending sweep: reaped %d abandoned pending row(s)", reaped)
		}
	}
}

// ListConsentRequests reads the durable console-consent requests for owner (empty = all) from the
// store: pending-first, newest-first. history includes resolved/expired rows. Fail-closed empty
// owner is the API's responsibility; the Registry just proxies the store read.
func (r *Registry) ListConsentRequests(owner string, history bool) ([]*store.ConsentRequest, error) {
	if r.st == nil {
		return nil, nil
	}
	return r.st.ListConsentRequests(context.Background(), owner, history)
}

// ServeHTTP routes an MCP request to the target's gateway (mount at "/mcp/{target}").
// When auth is on, the agent key is verified BEFORE anything is built: an unauthenticated
// request must not trigger credential unsealing or an upstream connect, and it learns nothing
// about which target ids exist (uniform 401 — the entitlement check subsumes existence).
// For authenticated callers, unknown or disabled targets are a plain 404; a build failure is
// a 502 and is retried on the next request.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("target")
	if id == "" {
		http.NotFound(w, req)
		return
	}
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gw, err := r.get(req.Context(), id)
		switch {
		case err == nil:
			gw.Handler().ServeHTTP(w, req)
		case errors.Is(err, store.ErrNotFound) || errors.Is(err, errDisabled):
			http.NotFound(w, req)
		default:
			log.Printf("[delegent] gateway for target %q failed to build: %v", id, err)
			http.Error(w, "gateway unavailable", http.StatusBadGateway)
		}
	})
	if AuthRequired(r.st) {
		h = auth.RequireBearerToken(makeVerifier(r.st, id), &auth.RequireBearerTokenOptions{})(h)
	}
	h.ServeHTTP(w, req)
}

// get returns the cached gateway for id, building it on first use. The target row is read
// fresh at build time, so an Invalidate + rebuild picks up new credentials/enabled state.
func (r *Registry) get(ctx context.Context, id string) (instance, error) {
	s := r.slot(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gw != nil {
		return s.gw, nil
	}
	target, err := r.st.GetTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	if !target.Enabled {
		return nil, errDisabled
	}
	// Build against the background context: the gateway (and its upstream MCP session)
	// outlives the request that triggered the build.
	gw, err := r.build(context.Background(), r.st, r.sealer, target)
	if err != nil {
		return nil, err // not cached — the next request retries
	}
	s.gw = gw
	return gw, nil
}

func (r *Registry) slot(id string) *slot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.slots[id]
	if !ok {
		s = &slot{}
		r.slots[id] = s
	}
	return s
}

// Invalidate closes and drops the cached gateway for a target (no-op if none is cached). The
// next request rebuilds it from the store — this is how console changes (enable/disable,
// credential replacement) take effect live in the same process. Live MCP sessions on the old
// instance are severed: clients get a session-not-found on their next request and re-initialize
// per the MCP spec; their grants rehydrate from the store, so no re-consent is needed.
func (r *Registry) Invalidate(targetID string) {
	// every aggregate mirrors the target set, so any target change stales them all;
	// dropped even when this target was never built (it may be NEW — aggregates must grow)
	r.dropAggregates()
	r.mu.Lock()
	s, ok := r.slots[targetID]
	r.mu.Unlock()
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gw != nil {
		s.gw.Close()
		s.gw = nil
		log.Printf("[delegent] gateway for target %q invalidated — will rebuild on next request", targetID)
	}
}

// builtInstances snapshots the currently-built gateways (a target with no live traffic has no
// instance yet, so it has no pending consents to show). The snapshot is taken under the registry
// lock but each gateway is read outside it.
func (r *Registry) builtInstances() []instance {
	r.mu.Lock()
	slots := make([]*slot, 0, len(r.slots))
	for _, s := range r.slots {
		slots = append(slots, s)
	}
	r.mu.Unlock()
	var out []instance
	for _, s := range slots {
		s.mu.Lock()
		gw := s.gw
		s.mu.Unlock()
		if gw != nil {
			out = append(out, gw)
		}
	}
	return out
}

// PendingConsents collects the live, unused console-consent requests across every built gateway
// whose principal (target owner) matches owner — empty owner returns all. This is the console's
// read model: the web console passes the authenticated operator's user id so an operator sees only their own asks.
func (r *Registry) PendingConsents(owner string) []PendingView {
	var out []PendingView
	for _, gw := range r.builtInstances() {
		out = append(out, gw.PendingViews(owner)...)
	}
	return out
}

// ResolveConsent applies a human decision to pending id wherever it lives: it tries each built
// gateway until one owns the id (grant → that gateway mints on the SAME broker path the widget
// uses; deny → empty granted). ok=false when no gateway holds the id (unknown/expired/already
// resolved) — safe to call blind. Deny is expressed as an empty granted slice.
func (r *Registry) ResolveConsent(owner, id string, granted []string, ttlMinutes int, budgetUSD float64) (ok bool, err error) {
	d := consoleDecision{owner: owner, granted: granted, ttlMinutes: ttlMinutes, budgetUSD: budgetUSD}
	for _, gw := range r.builtInstances() {
		if found, _, _ := gw.ResolvePending(id, d); found {
			return true, nil
		}
	}
	// No live in-memory record holds this id — the gateway was rebuilt/restarted since the
	// request parked, so the waiting agent is gone and there is no connection to bind a grant
	// to. If a pending DB row for this owner still exists, reconcile it to "expired" now (rather
	// than leave a ghost row that looks approvable but 404s until the TTL sweep). The agent
	// re-requests on its next call. Returns ok=false either way (no grant is minted).
	r.reconcileOrphan(owner, id)
	return false, nil
}

// reconcileOrphan expires an owner's pending consent_requests row whose in-memory record is
// gone. Best-effort and owner-scoped; a row belonging to another owner or already resolved is
// left untouched.
func (r *Registry) reconcileOrphan(owner, id string) {
	if r.st == nil {
		return
	}
	ctx := context.Background()
	row, err := r.st.GetConsentRequest(ctx, id)
	if err != nil || row == nil || row.Principal != owner || row.Status != "pending" {
		return
	}
	row.Status = "expired"
	row.ResolvedAt = nowMillis()
	if err := r.st.PutConsentRequest(ctx, row); err != nil {
		return
	}
	r.hub.publish(ConsentEvent{Type: "resolved", Owner: owner, ID: id})
	log.Printf("[delegent] consent request %s expired on resolve — its gateway was rebuilt; the agent will re-request", id)
}

// SubscribeConsent returns a channel of console park/resolve events and a cancel func that
// unsubscribes. The API's SSE handler drains it, filtering by owner.
func (r *Registry) SubscribeConsent() (<-chan ConsentEvent, func()) {
	return r.hub.subscribe()
}
