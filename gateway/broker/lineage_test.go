package broker_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"delegent.dev/gateway/broker"
	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/loader"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

// grantLong answers every consent with GRANT and a long TTL, to exercise the expiry cap.
type grantLong struct{}

func (grantLong) Ask(req controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	var g []string
	for _, s := range req.Scopes {
		g = append(g, s.Scope)
	}
	return &controlplane.ConsentAnswer{Granted: g, TTLMinutes: 600, BudgetUSD: 5}, nil
}

// newBrokerOn builds a broker for vendor over a SHARED store, so two targets can be modelled
// in one test (a cross-agent hop is a session on one vendor parented to a session on another).
func newBrokerOn(t *testing.T, st *store.MemStore, vendor string) *broker.Broker {
	t.Helper()
	adapter, err := loader.Adapter("../testdata/adapters/mcp-remote/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	advisor, _ := loader.LoadAdvisor("../testdata/adapters/mcp-remote/advisor.json")
	principals, _ := loader.LoadPrincipals("../testdata/adapters/mcp-remote/principals.json")
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if _, err := st.GetUser(context.Background(), "root:alice"); err != nil {
		if err := st.PutUser(context.Background(), &store.User{ID: "root:alice"}); err != nil {
			t.Fatal(err)
		}
	}
	rk := rootkeys.New(st, sealer)
	if _, err := rk.Ensure(context.Background(), "root:alice"); err != nil {
		t.Fatal(err)
	}
	var i int
	cp := controlplane.New(controlplane.Options{
		Vendor: vendor, Adapter: adapter, Advisor: advisor, Principals: principals.Principals,
		RootName: "root:alice", RootKeys: rk, Store: st,
		Now: func() int64 { return 1000 }, Rand: func() string { i++; return vendor + "-r" + strconv.Itoa(i) },
	})
	var j int
	return broker.New(cp, st, sealer, func() int64 { return 1000 }, func() string { j++; return vendor + "-b" + strconv.Itoa(j) })
}

func session(t *testing.T, st store.Store, handle string) *store.Session {
	t.Helper()
	ss, err := st.GetSession(context.Background(), handle)
	if err != nil {
		t.Fatalf("session %s: %v", handle, err)
	}
	return ss
}

func depthOf(t *testing.T, st store.Store, handle string) int {
	t.Helper()
	ss := session(t, st, handle)
	var body core.SlipBody
	last := ss.Chain[len(ss.Chain)-1]
	if err := jsonUnmarshal(last.Canonical, &body); err != nil {
		t.Fatal(err)
	}
	return body.Depth
}

// --- the escalation fix: an escalated grant is tied to the run and can never be passed on ---

// Human path: no ancestor holds the scope, the human grants it. The result must not be
// narrowable (depth 0), must expire no later than the requester, and must be parented to the
// requester so lineage and chain revocation work.
func TestEscalateToHumanIsNotPassableOn(t *testing.T) {
	st := store.NewMemStore()
	b := newBrokerOn(t, st, "mcp-remote")
	root, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "summarize", grantAll{})
	child, _, ok := b.Narrow(root, broker.NarrowOpts{Scopes: []string{"mcp:connect", "files:read"}, Minutes: intp(10)})
	if !ok {
		t.Fatal("narrow failed")
	}
	allow(t, b, child, "write_file", false)

	msg, granted := b.Escalate(child, []string{"files:write"}, "need to save", grantLong{})
	if !granted || !strings.Contains(msg, "escalated to the human") {
		t.Fatalf("expected a human grant, got granted=%v msg=%s", granted, msg)
	}
	esc := extractSession(msg)
	allow(t, b, esc, "write_file", true)

	if _, m, ok := b.Narrow(esc, broker.NarrowOpts{Scopes: []string{"files:write"}}); ok || !strings.Contains(m, "depth exhausted") {
		t.Fatalf("an escalated grant must not be narrowable: ok=%v msg=%s", ok, m)
	}
	if d := depthOf(t, st, esc); d != 0 {
		t.Errorf("escalated depth = %d, want 0", d)
	}
	reqExp, escExp := session(t, st, child).ExpiresAt, session(t, st, esc).ExpiresAt
	if escExp > reqExp {
		t.Errorf("escalated grant expires at %d, after its requester (%d)", escExp, reqExp)
	}
	if p := session(t, st, esc).ParentHandle; p != child {
		t.Errorf("escalated grant parent = %q, want the requester %s", p, child)
	}
	// Revoking the requester's chain takes the escalated grant down with it.
	if n := b.RevokeSelf(child, true); n != 2 {
		t.Errorf("chain revoke flipped %d sessions, want 2 (requester + escalated)", n)
	}
	if b.SessionLive(esc) {
		t.Error("escalated grant still live after its requester's chain was revoked")
	}
}

// Ancestor path: the parent approves. The hand-down is likewise depth 0 and capped at the
// requester's expiry.
func TestApprovedEscalationIsNotPassableOn(t *testing.T) {
	st := store.NewMemStore()
	b := newBrokerOn(t, st, "mcp-remote")
	parent, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit", grantAll{})
	child, _, _ := b.Narrow(parent, broker.NarrowOpts{Effects: []string{"read"}, Scopes: []string{"mcp:connect", "files:read"}, Minutes: intp(5)})
	msg, granted := b.Escalate(child, []string{"files:write"}, "need to save", grantAll{})
	if granted {
		t.Fatalf("expected pending, got %s", msg)
	}
	pend := b.PendingEscalations(parent)
	amsg, ok := b.ApproveEscalation(parent, pend[0].ID)
	if !ok {
		t.Fatal(amsg)
	}
	esc := extractSession(amsg)
	allow(t, b, esc, "write_file", true)
	if _, m, ok := b.Narrow(esc, broker.NarrowOpts{}); ok || !strings.Contains(m, "depth exhausted") {
		t.Fatalf("an approved escalation must not be narrowable: ok=%v msg=%s", ok, m)
	}
	if reqExp, escExp := session(t, st, child).ExpiresAt, session(t, st, esc).ExpiresAt; escExp > reqExp {
		t.Errorf("hand-down expires at %d, after its requester (%d)", escExp, reqExp)
	}
}

// --- cross-agent hops: GrantUnder ---

// A call that echoes its caller's session opens a CHILD session: one hop less of depth, expiry
// capped at the parent's, parented for lineage — even though it lives on another target.
func TestGrantUnderOpensChildHop(t *testing.T) {
	st := store.NewMemStore()
	researcher := newBrokerOn(t, st, "researcher")
	mailer := newBrokerOn(t, st, "mailer")

	parent, _, ok := researcher.GrantUnder("root:alice", "", []string{"mcp:connect", "files:read"}, "research", grantAll{}, broker.Lineage{Label: "laptop@researcher"})
	if !ok {
		t.Fatal("root grant failed")
	}
	child, msg, ok := mailer.GrantUnder("root:alice", "", []string{"mcp:connect", "mail:send"}, "tool: send_email", grantLong{}, broker.Lineage{Parent: parent, Label: "agent:researcher@mailer"})
	if !ok {
		t.Fatalf("child grant failed: %s", msg)
	}
	allow(t, mailer, child, "send_email", true)

	if got, want := depthOf(t, st, child), depthOf(t, st, parent)-1; got != want {
		t.Errorf("child depth = %d, want parent-1 = %d", got, want)
	}
	if pExp, cExp := session(t, st, parent).ExpiresAt, session(t, st, child).ExpiresAt; cExp != pExp {
		t.Errorf("child expiry %d not capped at the parent's %d (the human chose a longer TTL)", cExp, pExp)
	}
	if name := mailer.AgentDisplayName(child); name != "laptop@researcher→agent:researcher@mailer" {
		t.Errorf("display name = %q", name)
	}
	// The chain is one unit: revoking the parent's chain revokes the hop on the other target.
	researcher.RevokeSelf(parent, true)
	if mailer.SessionLive(child) {
		t.Error("child hop still live after the parent's chain was revoked")
	}
}

func TestGrantUnderRefusesBadParents(t *testing.T) {
	st := store.NewMemStore()
	b := newBrokerOn(t, st, "mailer")
	if _, msg, ok := b.GrantUnder("root:alice", "", []string{"mcp:connect"}, "x", grantAll{}, broker.Lineage{Parent: "sess_nope"}); ok || !strings.Contains(msg, "unknown") {
		t.Errorf("unknown parent: ok=%v msg=%s", ok, msg)
	}
	root, _, _ := b.Open("root:alice", []string{"mcp:connect"}, "x", grantAll{})
	b.RevokeSelf(root, false)
	if _, msg, ok := b.GrantUnder("root:alice", "", []string{"mcp:connect"}, "x", grantAll{}, broker.Lineage{Parent: root}); ok || !strings.Contains(msg, "no longer live") {
		t.Errorf("revoked parent: ok=%v msg=%s", ok, msg)
	}
}

// Every hop spends one unit of depth; the leaf cannot hand work on.
func TestGrantUnderDepthExhausted(t *testing.T) {
	t.Setenv("DELEGENT_MAX_DEPTH", "1")
	st := store.NewMemStore()
	a := newBrokerOn(t, st, "assistant")
	r := newBrokerOn(t, st, "researcher")
	l := newBrokerOn(t, st, "librarian")
	h1, _, _ := a.Open("root:alice", []string{"mcp:connect"}, "plan", grantAll{})
	h2, msg, ok := r.GrantUnder("root:alice", "", []string{"mcp:connect"}, "research", grantAll{}, broker.Lineage{Parent: h1})
	if !ok {
		t.Fatalf("hop 1: %s", msg)
	}
	if _, msg, ok := l.GrantUnder("root:alice", "", []string{"mcp:connect"}, "lookup", grantAll{}, broker.Lineage{Parent: h2}); ok || !strings.Contains(msg, "depth exhausted") {
		t.Errorf("hop 2 past the depth limit: ok=%v msg=%s", ok, msg)
	}
}

// An ancestor on another target never counts as "holding" a scope, even when the scope names
// collide across targets.
func TestEscalateSkipsAncestorsOnOtherTargets(t *testing.T) {
	st := store.NewMemStore()
	researcher := newBrokerOn(t, st, "researcher")
	mailer := newBrokerOn(t, st, "mailer")
	parent, _, _ := researcher.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit", grantAll{})
	child, _, _ := mailer.GrantUnder("root:alice", "", []string{"mcp:connect", "files:read"}, "x", grantAll{}, broker.Lineage{Parent: parent})
	msg, _ := mailer.Escalate(child, []string{"files:write"}, "more", grantAll{})
	if !strings.Contains(msg, "escalated to the human") {
		t.Fatalf("the researcher session's files:write must not satisfy a mailer escalation; got %s", msg)
	}
}

func intp(n int) *int { return &n }

func TestCheckLineage(t *testing.T) {
	t.Setenv("DELEGENT_MAX_DEPTH", "1")
	st := store.NewMemStore()
	b := newBrokerOn(t, st, "x")
	if why := b.CheckLineage("root:alice", ""); why != "" {
		t.Errorf("no parent must pass: %s", why)
	}
	if why := b.CheckLineage("root:alice", "sess_nope"); !strings.Contains(why, "unknown") {
		t.Errorf("unknown parent: %q", why)
	}
	root, _, _ := b.Open("root:alice", []string{"mcp:connect"}, "x", grantAll{})
	if why := b.CheckLineage("root:alice", root); why != "" {
		t.Errorf("live parent with depth must pass: %s", why)
	}
	if why := b.CheckLineage("root:bob", root); !strings.Contains(why, "another principal") {
		t.Errorf("foreign principal: %q", why)
	}
	leaf, _, _ := b.GrantUnder("root:alice", "", []string{"mcp:connect"}, "x", grantAll{}, broker.Lineage{Parent: root})
	if why := b.CheckLineage("root:alice", leaf); !strings.Contains(why, "depth exhausted") {
		t.Errorf("depth-0 parent: %q", why)
	}
}
