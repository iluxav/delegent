package telegram

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"delegent.dev/gateway/store"
)

type fakeResolver struct {
	calls []struct {
		owner, id string
		granted   []string
	}
	ok bool
}

func (f *fakeResolver) ResolveConsent(owner, id string, granted []string, ttlMinutes int, budgetUSD float64) (bool, error) {
	f.calls = append(f.calls, struct {
		owner, id string
		granted   []string
	}{owner, id, granted})
	return f.ok, nil
}

func decisionFixture(t *testing.T) (*store.MemStore, *fakeResolver, DecisionHandler) {
	t.Helper()
	st := store.NewMemStore()
	ctx := context.Background()
	_ = st.PutConsentRequest(ctx, &store.ConsentRequest{
		ID: "creq_7", TargetID: "gh", Principal: "usr_op", AgentName: "claude-code",
		Scopes: []string{"files:write", "files:read"}, Status: "pending",
		CreatedAt: 1, ExpiresAt: 9_000_000_000_000,
	})
	_ = st.PutChannelConnection(ctx, &store.ChannelConnection{UserID: "usr_op", Kind: "telegram", Address: "555"})
	rs := &fakeResolver{ok: true}
	return st, rs, NewDecisionHandler(st, rs)
}

func TestDecisionApproveGrantsAskedScopes(t *testing.T) {
	_, rs, h := decisionFixture(t)
	result := h(context.Background(), "creq_7", "grant", "555", "ilya")
	if len(rs.calls) != 1 {
		t.Fatalf("resolver calls: %+v", rs.calls)
	}
	c := rs.calls[0]
	if c.owner != "usr_op" || c.id != "creq_7" || !reflect.DeepEqual(c.granted, []string{"files:write", "files:read"}) {
		t.Fatalf("resolve call: %+v", c)
	}
	for _, want := range []string{"Approved", "files:write"} {
		if !strings.Contains(result, want) {
			t.Fatalf("result missing %q: %q", want, result)
		}
	}
}

func TestDecisionDenyGrantsNothing(t *testing.T) {
	_, rs, h := decisionFixture(t)
	result := h(context.Background(), "creq_7", "deny", "555", "ilya")
	if len(rs.calls) != 1 || rs.calls[0].granted != nil {
		t.Fatalf("deny must resolve with no scopes: %+v", rs.calls)
	}
	if !strings.Contains(result, "Denied") {
		t.Fatalf("result: %q", result)
	}
}

// The tapping chat must be the owner's linked chat — a forwarded message or another group
// member can never resolve someone else's request.
func TestDecisionRejectsForeignChat(t *testing.T) {
	_, rs, h := decisionFixture(t)
	result := h(context.Background(), "creq_7", "grant", "777", "eve")
	if len(rs.calls) != 0 {
		t.Fatalf("resolver must not be called from a foreign chat: %+v", rs.calls)
	}
	if result == "" || strings.Contains(result, "Approved") {
		t.Fatalf("foreign chat result: %q", result)
	}
}

func TestDecisionUnknownRequest(t *testing.T) {
	_, rs, h := decisionFixture(t)
	result := h(context.Background(), "creq_nope", "grant", "555", "ilya")
	if len(rs.calls) != 0 {
		t.Fatalf("resolver must not be called for an unknown request: %+v", rs.calls)
	}
	if result == "" || strings.Contains(result, "Approved") {
		t.Fatalf("unknown request result: %q", result)
	}
}

// The registry answers ok=false when the parked in-memory record is gone (gateway rebuilt,
// TTL passed, or already resolved) — the chat must say so rather than claim success.
func TestDecisionStaleRequest(t *testing.T) {
	_, rs, h := decisionFixture(t)
	rs.ok = false
	result := h(context.Background(), "creq_7", "grant", "555", "ilya")
	if strings.Contains(result, "Approved") {
		t.Fatalf("stale request must not read as approved: %q", result)
	}
	if !strings.Contains(strings.ToLower(result), "no longer") {
		t.Fatalf("stale result should explain: %q", result)
	}
}
