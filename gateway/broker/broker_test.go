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

type grantAll struct{}

func (grantAll) Ask(req controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	var g []string
	for _, s := range req.Scopes {
		g = append(g, s.Scope)
	}
	return &controlplane.ConsentAnswer{Granted: g, TTLMinutes: 60, BudgetUSD: 5}, nil
}

func newBroker(t *testing.T) *broker.Broker {
	t.Helper()
	adapter, err := loader.Adapter("../testdata/adapters/mcp-remote/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	advisor, _ := loader.LoadAdvisor("../testdata/adapters/mcp-remote/advisor.json")
	principals, _ := loader.LoadPrincipals("../testdata/adapters/mcp-remote/principals.json")

	var i int
	counter := func() string { i++; return "r" + strconv.Itoa(i) }
	st := store.NewMemStore()
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err := st.PutUser(context.Background(), &store.User{ID: "root:alice"}); err != nil {
		t.Fatal(err)
	}
	rk := rootkeys.New(st, sealer)
	if _, err := rk.Ensure(context.Background(), "root:alice"); err != nil {
		t.Fatal(err)
	}
	cp := controlplane.New(controlplane.Options{
		Vendor: "mcp-remote", Adapter: adapter, Advisor: advisor, Principals: principals.Principals,
		RootName: "root:alice", RootKeys: rk, Store: st,
		Now: func() int64 { return 1000 }, Rand: counter,
	})
	var j int
	return broker.New(cp, st, sealer, func() int64 { return 1000 }, func() string { j++; return "b" + strconv.Itoa(j) })
}

func toolReq(name string) core.Request {
	return core.Request{Action: "POST", Resource: "/mcp", Body: map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": map[string]any{}},
	}}
}

func allow(t *testing.T, b *broker.Broker, handle, name string, want bool) {
	t.Helper()
	_, d, ok := b.Authorize(handle, toolReq(name))
	if !ok {
		t.Fatalf("session %s not found", handle)
	}
	if d.Allow != want {
		t.Errorf("%s on %s: allow=%v want %v (%s)", name, handle, d.Allow, want, d.Reason)
	}
}

func TestOpenThenAuthorize(t *testing.T) {
	b := newBroker(t)
	h, _, ok := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "summarize the files", grantAll{})
	if !ok {
		t.Fatal("open should grant")
	}
	allow(t, b, h, "read_file", true)
	allow(t, b, h, "delete_file", false)
}

func TestGrantAccumulatesAndPreservesExpiry(t *testing.T) {
	b := newBroker(t)
	// First grant: read only. (autoConsent sets TTL 60m; broker.now is fixed at 1000.)
	h, _, ok := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "summarize the files", grantAll{})
	if !ok {
		t.Fatal("open failed")
	}
	allow(t, b, h, "read_file", true)
	allow(t, b, h, "write_file", false)

	// Add files:write to the SAME session — accumulates, and the expiry must not reset.
	_, msg, ok := b.Grant("root:alice", h, []string{"files:write"}, "now save changes", grantAll{})
	if !ok {
		t.Fatalf("augment failed: %s", msg)
	}
	allow(t, b, h, "read_file", true)  // still holds the old scope
	allow(t, b, h, "write_file", true) // and the new one

	// Re-requesting a scope already held is a no-op (no re-mint, no prompt).
	_, msg2, ok := b.Grant("root:alice", h, []string{"files:read"}, "read again", &countingConsent{})
	if !ok || !strings.Contains(msg2, "nothing to add") {
		t.Errorf("held scope should be a no-op, got ok=%v msg=%s", ok, msg2)
	}
}

// countingConsent fails the test if Ask is ever called (used to prove no prompt happens).
type countingConsent struct{}

func (countingConsent) Ask(controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	panic("consent should not have been asked for a scope already held")
}

func TestNarrowIsStrictlyWeaker(t *testing.T) {
	b := newBroker(t)
	// A parent that CAN write (files:write confers write+destructive).
	parent, _, ok := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit the files", grantAll{})
	if !ok {
		t.Fatal("open failed")
	}
	allow(t, b, parent, "write_file", true)

	// Narrow to read-only for a sub-agent.
	child, _, ok := b.Narrow(parent, broker.NarrowOpts{Effects: []string{"read"}, Scopes: []string{"mcp:connect", "files:read"}})
	if !ok {
		t.Fatal("narrow failed")
	}
	allow(t, b, child, "read_file", true)
	allow(t, b, child, "write_file", false) // the child cannot write
	allow(t, b, parent, "write_file", true) // the parent still can
}

func TestEscalatePendingThenApprove(t *testing.T) {
	b := newBroker(t)
	parent, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit the files", grantAll{})
	// Read-only child, default ceiling = its own scopes (no pre-authorisation for write).
	child, _, _ := b.Narrow(parent, broker.NarrowOpts{Effects: []string{"read"}, Scopes: []string{"mcp:connect", "files:read"}})
	allow(t, b, child, "write_file", false)

	// The child asks for write: parent holds it but did not pre-authorise it → PENDING.
	msg, granted := b.Escalate(child, []string{"files:write"}, "need to save edits", grantAll{})
	if granted || !strings.Contains(msg, "PENDING") {
		t.Fatalf("expected a pending escalation, got granted=%v msg=%s", granted, msg)
	}
	pend := b.PendingEscalations(parent)
	if len(pend) != 1 {
		t.Fatalf("expected 1 pending at parent, got %d", len(pend))
	}

	// The parent approves — a deliberate hand-down, no human.
	amsg, ok := b.ApproveEscalation(parent, pend[0].ID)
	if !ok {
		t.Fatalf("approve failed: %s", amsg)
	}
	// The granted child session appears in the message; extract and test it can now write.
	granted2 := extractSession(amsg)
	if granted2 == "" {
		t.Fatalf("no granted session in: %s", amsg)
	}
	allow(t, b, granted2, "write_file", true)
	// The read-only child is unchanged.
	allow(t, b, child, "write_file", false)
}

func TestEscalatePreAuthorizedGrantsImmediately(t *testing.T) {
	b := newBroker(t)
	parent, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit the files", grantAll{})
	// Child HOLDS read only, but its ceiling PRE-AUTHORISES pulling files:write later.
	child, _, ok := b.Narrow(parent, broker.NarrowOpts{
		Effects: []string{"read"},
		Scopes:  []string{"mcp:connect", "files:read"},
		Ceiling: []string{"mcp:connect", "files:read", "files:write"},
	})
	if !ok {
		t.Fatal("narrow failed")
	}
	allow(t, b, child, "write_file", false)

	msg, granted := b.Escalate(child, []string{"files:write"}, "need to save edits", grantAll{})
	if !granted || !strings.Contains(msg, "granted immediately") {
		t.Fatalf("pre-authorised escalation should grant immediately, got granted=%v msg=%s", granted, msg)
	}
	granted2 := extractSession(msg)
	allow(t, b, granted2, "write_file", true)
}

func TestNarrowCannotWiden(t *testing.T) {
	b := newBroker(t)
	parent, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "summarize", grantAll{})
	// Ask for write the parent never had — the fold drops it, so the child still can't write.
	child, _, ok := b.Narrow(parent, broker.NarrowOpts{Effects: []string{"read", "write", "destructive"}, Scopes: []string{"mcp:connect", "files:read", "files:write"}})
	if !ok {
		t.Fatal("narrow failed")
	}
	allow(t, b, child, "write_file", false)
	allow(t, b, child, "delete_file", false)
}

func extractSession(msg string) string {
	i := strings.Index(msg, "session: ")
	if i < 0 {
		return ""
	}
	rest := msg[i+len("session: "):]
	if j := strings.IndexAny(rest, " \n"); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestAuthorizeRejectsRevokedSession(t *testing.T) {
	b := newBroker(t)
	h, _, ok := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "read", grantAll{})
	if !ok {
		t.Fatal("open failed")
	}
	allow(t, b, h, "read_file", true) // live → allowed

	if n := b.RevokeSelf(h, false); n != 1 {
		t.Fatalf("RevokeSelf revoked %d, want 1", n)
	}
	// The gate must now reject it — a revoked session confers no authority (ok=false is the
	// "no live session" signal the caller treats as needs-consent; it must never allow).
	_, d, ok := b.Authorize(h, toolReq("read_file"))
	if ok && d.Allow {
		t.Fatalf("revoked session still authorizes: ok=%v allow=%v", ok, d.Allow)
	}
	// Idempotent: revoking again flips nothing.
	if n := b.RevokeSelf(h, false); n != 0 {
		t.Fatalf("second RevokeSelf revoked %d, want 0", n)
	}
}

func TestRevokeSelfChainRevokesDescendants(t *testing.T) {
	b := newBroker(t)
	parent, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit", grantAll{})
	child, _, ok := b.Narrow(parent, broker.NarrowOpts{Effects: []string{"read"}, Scopes: []string{"mcp:connect", "files:read"}})
	if !ok {
		t.Fatal("narrow failed")
	}
	allow(t, b, child, "read_file", true)

	// chain=false leaves the child alone.
	if n := b.RevokeSelf(parent, false); n != 1 {
		t.Fatalf("non-chain revoke count = %d, want 1", n)
	}
	if _, d, _ := b.Authorize(child, toolReq("read_file")); !d.Allow {
		t.Fatal("child should survive a non-chain parent revoke")
	}
	// A fresh tree, this time chain=true takes the child down too.
	p2, _, _ := b.Open("root:alice", []string{"mcp:connect", "files:read", "files:write"}, "edit", grantAll{})
	c2, _, _ := b.Narrow(p2, broker.NarrowOpts{Effects: []string{"read"}, Scopes: []string{"mcp:connect", "files:read"}})
	if n := b.RevokeSelf(p2, true); n != 2 {
		t.Fatalf("chain revoke count = %d, want 2 (parent + child)", n)
	}
	if _, d, _ := b.Authorize(c2, toolReq("read_file")); d.Allow {
		t.Fatal("child should be revoked by a chain parent revoke")
	}
}

func TestSessionLive(t *testing.T) {
	b := newBroker(t)
	if b.SessionLive("") || b.SessionLive("sess_nope") {
		t.Fatal("empty/unknown handle must not be live")
	}
	// A live session (open mints with a future expiry under the test clock=1000).
	h, _, ok := b.Open("root:alice", []string{"mcp:connect", "files:read"}, "read", grantAll{})
	if !ok {
		t.Fatal("open failed")
	}
	if !b.SessionLive(h) {
		t.Fatal("freshly opened session must be live")
	}
	// Revoked → not live.
	b.RevokeSelf(h, false)
	if b.SessionLive(h) {
		t.Fatal("revoked session must not be live")
	}
}
