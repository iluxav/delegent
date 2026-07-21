package controlplane

import (
	"context"
	"strings"
	"testing"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/loader"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

func newCP(t *testing.T) *ControlPlane {
	t.Helper()
	adapter, err := loader.Adapter("../testdata/adapters/mcp-remote/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	advisor, err := loader.LoadAdvisor("../testdata/adapters/mcp-remote/advisor.json")
	if err != nil {
		t.Fatal(err)
	}
	principals, err := loader.LoadPrincipals("../testdata/adapters/mcp-remote/principals.json")
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	sealer, _ := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err := st.PutUser(context.Background(), &store.User{ID: "root:alice"}); err != nil {
		t.Fatal(err)
	}
	rk := rootkeys.New(st, sealer)
	if _, err := rk.Ensure(context.Background(), "root:alice"); err != nil {
		t.Fatal(err)
	}
	return New(Options{
		Vendor: "mcp-remote", Adapter: adapter, Advisor: advisor, Principals: principals.Principals,
		RootName: "root:alice", RootKeys: rk, Store: st,
		Now: func() int64 { return 1000 }, Rand: func() string { return "nonce1" },
	})
}

type autoConsent struct {
	ttl    int
	budget float64
}

func (a autoConsent) Ask(req ConsentRequest) (*ConsentAnswer, error) {
	var g []string
	for _, s := range req.Scopes {
		g = append(g, s.Scope)
	}
	return &ConsentAnswer{Granted: g, TTLMinutes: a.ttl, BudgetUSD: a.budget}, nil
}

type captureConsent struct {
	got    ConsentRequest
	answer *ConsentAnswer
}

func (c *captureConsent) Ask(req ConsentRequest) (*ConsentAnswer, error) {
	c.got = req
	return c.answer, nil
}

func TestGrantMintsSlip(t *testing.T) {
	cp := newCP(t)
	agentPub, _, _ := core.NewKeypair()
	res := cp.RequestAccess("root:alice", []string{"mcp:connect", "files:read"}, "summarize the files", agentPub, autoConsent{60, 1})

	if !res.Granted {
		t.Fatalf("should grant, got: %s", res.Message)
	}
	if len(res.Chain) != 1 {
		t.Fatalf("expected a 1-slip chain, got %d", len(res.Chain))
	}
	if res.Effects != core.EffectRead {
		t.Errorf("effects = %s, want read", core.EffectNames(res.Effects))
	}
	if res.Chain[0].Body.Aud != agentPub {
		t.Error("slip must be bound to the caller's key")
	}
	if res.Chain[0].Body.Exp != 1000+60*60_000 {
		t.Errorf("exp not derived from ttl: %d", res.Chain[0].Body.Exp)
	}
}

func TestUngrantableRefused(t *testing.T) {
	cp := newCP(t)
	agentPub, _, _ := core.NewKeypair()
	// Alice holds no mcp:sampling — she cannot consent to authority she lacks.
	res := cp.RequestAccess("root:alice", []string{"mcp:sampling"}, "let the server generate summaries", agentPub, autoConsent{60, 1})
	if res.Granted {
		t.Fatal("mcp:sampling must not be grantable")
	}
	if !strings.Contains(res.Message, "does not hold") {
		t.Errorf("message should explain the entitlement gap, got: %s", res.Message)
	}
}

func TestOverAskSurfacedBeforeGrant(t *testing.T) {
	cp := newCP(t)
	agentPub, _, _ := core.NewKeypair()
	cap := &captureConsent{answer: &ConsentAnswer{Granted: []string{"mcp:connect", "files:read"}, TTLMinutes: 60, BudgetUSD: 1}}

	// Reason justifies read only; the request over-asks for write + mail.
	cp.RequestAccess("root:alice", []string{"mcp:connect", "files:read", "files:write", "mail:send"}, "summarize the files", agentPub, cap)

	if len(cap.got.OverAsk) != 2 || !contains(cap.got.OverAsk, "files:write") || !contains(cap.got.OverAsk, "mail:send") {
		t.Errorf("over-ask should name files:write and mail:send, got %v", cap.got.OverAsk)
	}
	if len(cap.got.OverAskWarnings) != 2 {
		t.Errorf("expected 2 over-ask warnings, got %d", len(cap.got.OverAskWarnings))
	}
}

func TestDeclineMintsNothing(t *testing.T) {
	cp := newCP(t)
	agentPub, _, _ := core.NewKeypair()
	declined := &captureConsent{answer: nil}
	res := cp.RequestAccess("root:alice", []string{"mcp:connect", "files:read"}, "summarize the files", agentPub, declined)
	if res.Granted {
		t.Fatal("a declined consent must mint nothing")
	}
}

func TestAllScopesReturnsSortedAdvisorKeys(t *testing.T) {
	cp := newCP(t)
	got := cp.AllScopes()
	want := []string{"billing:spend", "files:read", "files:write", "mail:send", "mcp:connect", "mcp:elicit", "mcp:roots", "mcp:sampling"}
	if len(got) != len(want) {
		t.Fatalf("AllScopes returned %d scopes, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllScopes not sorted or wrong at %d: got %v want %v", i, got, want)
		}
	}
}

func TestAllScopesEmptyWithoutAdvisor(t *testing.T) {
	cp := New(Options{Vendor: "v", RootName: "root:alice"})
	if got := cp.AllScopes(); len(got) != 0 {
		t.Fatalf("no advisor must yield no scopes, got %v", got)
	}
}
