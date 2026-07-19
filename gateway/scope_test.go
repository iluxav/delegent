package gateway

import (
	"context"
	"strconv"
	"strings"
	"testing"

	core "delegent.dev/protocol"
	"delegent.dev/gateway/broker"
	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/loader"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/store"
)

// grantAll answers every consent dialog with GRANT on all offered scopes.
type grantAll struct{}

func (grantAll) Ask(req controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	var g []string
	for _, s := range req.Scopes {
		g = append(g, s.Scope)
	}
	return &controlplane.ConsentAnswer{Granted: g, TTLMinutes: 60, BudgetUSD: 5}, nil
}

// scopeGateway assembles a Gateway around a real broker/control-plane (no upstream MCP
// connection — the tests drive resumeSession/broker directly, the same internals the
// handlers use) with the given grant scope.
func scopeGateway(t *testing.T, scope string) *Gateway {
	t.Helper()
	adapter, err := loader.Adapter("testdata/adapters/mcp-remote/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	advisor, _ := loader.LoadAdvisor("testdata/adapters/mcp-remote/advisor.json")
	principals, _ := loader.LoadPrincipals("testdata/adapters/mcp-remote/principals.json")

	st := store.NewMemStore()
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err := st.PutUser(context.Background(), &store.User{ID: "root:alice"}); err != nil {
		t.Fatal(err)
	}
	rk := rootkeys.New(st, sealer)
	if _, err := rk.Ensure(context.Background(), "root:alice"); err != nil {
		t.Fatal(err)
	}
	var i int
	cp := controlplane.New(controlplane.Options{
		Vendor: "mcp-remote", Adapter: adapter, Advisor: advisor, Principals: principals.Principals,
		RootName: "root:alice", RootKeys: rk, Store: st,
		Now: func() int64 { return 1000 }, Rand: func() string { i++; return "r" + strconv.Itoa(i) },
	})
	var j int
	br := broker.New(cp, st, sealer, func() int64 { return 1000 }, func() string { j++; return "b" + strconv.Itoa(j) })
	var k int
	return &Gateway{
		targetID: "mcp-remote", cp: cp, br: br, st: st, adapter: adapter,
		byConn: map[string]string{}, byConnCaps: map[string]clientCaps{}, byConnMeta: map[string]callMeta{},
		pending:          newPendingStore(func() int64 { return 1000 }, func() string { k++; return "req_" + strconv.Itoa(k) }),
		defaultPrincipal: "root:alice", grantScope: scope,
		scopeTools: buildScopeTools(adapter, []string{"read_file", "search_files", "write_file", "delete_file", "send_email", "purchase"}),
	}
}

func toolReq(name string) core.Request {
	return core.Request{Action: "POST", Resource: "/mcp", Body: map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": map[string]any{}},
	}}
}

// Connection scope (the default): two connections of the SAME principal each mint their own
// session and never see each other's grants.
func TestConnectionScopeIsolatesConnections(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)

	// Connection A consents to files:read and accumulates its session.
	hA, msg, ok := g.br.Grant("root:alice", "", []string{"mcp:connect", "files:read"}, "read the notes", grantAll{})
	if !ok {
		t.Fatalf("grant on connA failed: %s", msg)
	}
	g.setSession("connA", hA)
	if got := g.resumeSession("connA"); got != hA {
		t.Fatalf("connA must resume its own session, got %q want %q", got, hA)
	}

	// Connection B (same principal) must NOT inherit connA's live session.
	if got := g.resumeSession("connB"); got != "" {
		t.Fatalf("connection scope must not resume another connection's session, got %q", got)
	}

	// connB consents separately — a distinct session with its own scopes.
	hB, msg, ok := g.br.Grant("root:alice", "", []string{"mcp:connect", "files:write"}, "save the edits", grantAll{})
	if !ok {
		t.Fatalf("grant on connB failed: %s", msg)
	}
	g.setSession("connB", hB)
	if hA == hB {
		t.Fatal("the two connections must mint SEPARATE sessions")
	}

	// Neither session holds the other's grant.
	if _, d, ok := g.br.Authorize(hA, toolReq("write_file")); !ok || d.Allow {
		t.Errorf("connA's session must not hold connB's files:write grant (allow=%v)", d.Allow)
	}
	if _, d, ok := g.br.Authorize(hB, toolReq("read_file")); !ok || d.Allow {
		t.Errorf("connB's session must not hold connA's files:read grant (allow=%v)", d.Allow)
	}
	// And each connection keeps resuming only its own.
	if g.resumeSession("connA") != hA || g.resumeSession("connB") != hB {
		t.Fatal("connections must keep resuming their own sessions")
	}
}

// User scope (DELEGENT_GRANT_SCOPE=user): the old behavior — a new connection resumes the
// principal's latest live session from the store.
func TestUserScopeResumesLatestLiveSession(t *testing.T) {
	g := scopeGateway(t, grantScopeUser)

	h, msg, ok := g.br.Grant("root:alice", "", []string{"mcp:connect", "files:read"}, "read the notes", grantAll{})
	if !ok {
		t.Fatalf("grant failed: %s", msg)
	}
	// A brand-new connection (e.g. after a gateway rebuild) resumes it without re-consenting.
	if got := g.resumeSession("connNew"); got != h {
		t.Fatalf("user scope must resume the latest live session, got %q want %q", got, h)
	}
	if _, d, _ := g.br.Authorize(h, toolReq("read_file")); !d.Allow {
		t.Errorf("resumed session lost its grant: %s", d.Reason)
	}
}

func TestGrantScopeFromEnv(t *testing.T) {
	t.Setenv("DELEGENT_GRANT_SCOPE", "")
	if got := grantScopeFromEnv(); got != grantScopeConnection {
		t.Errorf("default scope = %q, want connection", got)
	}
	t.Setenv("DELEGENT_GRANT_SCOPE", "user")
	if got := grantScopeFromEnv(); got != grantScopeUser {
		t.Errorf("scope = %q, want user", got)
	}
	t.Setenv("DELEGENT_GRANT_SCOPE", "bogus")
	if got := grantScopeFromEnv(); got != grantScopeConnection {
		t.Errorf("unknown value must fall back to connection, got %q", got)
	}
}

// Sub-agent identity: narrow_access results carry the child's chain name.
func TestNarrowResultNamesTheChain(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	parent, _, ok := g.br.Grant("root:alice", "", []string{"mcp:connect", "files:read"}, "read", grantAll{})
	if !ok {
		t.Fatal("grant failed")
	}
	child, msg, ok := g.br.Narrow(parent, broker.NarrowOpts{Scopes: []string{"mcp:connect", "files:read"}})
	if !ok {
		t.Fatalf("narrow failed: %s", msg)
	}
	want := "main-agent-" + parent[len(parent)-8:] + "→sub-agent-" + child[len(child)-8:]
	if !strings.Contains(msg, want) {
		t.Errorf("narrow message %q does not carry the chain name %q", msg, want)
	}
}

// contains reports slice membership (test helper).
func sliceHas(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func findScope(available []planScope, scope string) (planScope, bool) {
	for _, s := range available {
		if s.Scope == scope {
			return s, true
		}
	}
	return planScope{}, false
}

// plan_access on a fresh connection lists the grantable capabilities with their tools, and its
// guidance states that access is additive (re-request anytime).
func TestPlanAccessListsGrantableWithTools(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)

	plan := g.planAccess("root:alice", "conn1")
	if len(plan.Held) != 0 {
		t.Fatalf("a fresh connection holds nothing, got %v", plan.Held)
	}
	fr, ok := findScope(plan.Available, "files:read")
	if !ok {
		t.Fatalf("files:read must be grantable, available = %v", plan.Available)
	}
	if !sliceHas(fr.Tools, "read_file") || !sliceHas(fr.Tools, "search_files") {
		t.Errorf("files:read should unlock read_file/search_files, got %v", fr.Tools)
	}
	if fr.Risk == "" {
		t.Error("files:read should carry a risk level")
	}
	// Alice is not entitled to mcp:sampling — it must never be offered.
	if _, ok := findScope(plan.Available, "mcp:sampling"); ok {
		t.Error("mcp:sampling is outside Alice's entitlements and must not be offered")
	}
	if !strings.Contains(strings.ToLower(plan.Guidance), "additive") {
		t.Errorf("guidance must state access is additive, got %q", plan.Guidance)
	}
	if !strings.Contains(plan.Guidance, "request_access") {
		t.Errorf("guidance must steer to request_access, got %q", plan.Guidance)
	}
}

// After a scope is granted (a live session holding it), plan_access no longer lists it as
// available — it moves to held. Proves the remaining-only / additive behavior.
func TestPlanAccessExcludesHeldScopes(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)

	h, msg, ok := g.br.Grant("root:alice", "", []string{"mcp:connect", "files:read"}, "read the notes", grantAll{})
	if !ok {
		t.Fatalf("grant failed: %s", msg)
	}
	g.setSession("conn1", h)

	plan := g.planAccess("root:alice", "conn1")
	if !sliceHas(plan.Held, "files:read") || !sliceHas(plan.Held, "mcp:connect") {
		t.Fatalf("held must include the granted scopes, got %v", plan.Held)
	}
	if _, ok := findScope(plan.Available, "files:read"); ok {
		t.Error("files:read is already held — it must not appear as available")
	}
	if _, ok := findScope(plan.Available, "mcp:connect"); ok {
		t.Error("mcp:connect is already held — it must not appear as available")
	}
	// A not-yet-held scope Alice is entitled to is still offered.
	if _, ok := findScope(plan.Available, "files:write"); !ok {
		t.Error("files:write is not held and within entitlements — it must still be available")
	}
}
