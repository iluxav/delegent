package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/store"
)

// okUpstream answers every call with "ok" — enough to see whether the guarded path let it out.
type okUpstream struct{ calls int }

func (u *okUpstream) Tools(context.Context) ([]*mcp.Tool, error) { return nil, nil }
func (u *okUpstream) Call(context.Context, UpstreamCall) (*mcp.CallToolResult, error) {
	u.calls++
	return text("ok"), nil
}
func (u *okUpstream) Close() {}

// A target's audience decides who may call it at all; its consent mode decides whether a
// permitted caller is asked; "always" on a consent is remembered for that key.
func TestAudienceConsentAndRemembered(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	up := &okUpstream{}
	g.upstream = up
	st := g.st
	tok, hash, _ := agentkey.New()
	ctx := context.Background()
	st.PutAgentKey(ctx, &store.AgentKey{ID: "akey_p", UserID: "root:alice", Hash: hash, Name: "planner", AgentTargetID: "planner"})
	call := func(kctx context.Context) string {
		res, err := g.guardedCall(kctx, "c1", nil, "read_file", map[string]any{"path": "x"}, "why", json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		return mustText(res, nil)
	}
	kctx := authedCtx(t, st, tok, nil)

	// the target as stored is what visibility reads; the gateway's copy carries consent
	setTarget := func(tt store.Target) {
		tt.ID, tt.Enabled = "mcp-remote", true
		st.PutTarget(ctx, &tt)
		g.access = tt
	}
	// no agent: an agent's key is refused before any consent, nothing forwarded
	setTarget(store.Target{Audience: store.AudienceHumans})
	if out := call(kctx); !strings.Contains(out, "not in the audience") || up.calls != 0 {
		t.Fatalf("no agent: %q calls=%d", out, up.calls)
	}
	// the agent's own exposure: planner uses only listed targets, and this one is not listed
	setTarget(store.Target{})
	st.PutTarget(ctx, &store.Target{ID: "planner", Kind: TargetKindA2A, Enabled: true, Uses: store.UsesListed})
	if out := call(kctx); !strings.Contains(out, "not in the audience") {
		t.Fatalf("uses listed (unrelated): %q", out)
	}
	st.PutRelation(ctx, &store.Relation{Agent: "planner", Target: "mcp-remote"})
	g.clearSession("c1")
	if out := call(kctx); !strings.Contains(out, "not granted") { // exposed, and asked (no dialog → deny)
		t.Fatalf("uses listed (related) must be asked: %q", out)
	}

	// consent allow: forwarded with no human, and the grant is on record
	setTarget(store.Target{Consent: store.ConsentAllow})
	g.clearSession("c1")
	if out := call(kctx); out != "ok" || up.calls != 1 {
		t.Fatalf("allow: %q calls=%d", out, up.calls)
	}
	if rs := g.cp.Receipts(); len(rs) == 0 || rs[len(rs)-1].Decision != "grant" {
		t.Fatalf("standing grant not receipted: %+v", rs)
	}

	// consent remember: a remembered "always" covers its scopes, nothing else — and it is
	// remembered for the AGENT (planner), not the key
	setTarget(store.Target{Consent: store.ConsentRemember})
	st.PutRemembered(ctx, &store.Remembered{Caller: "planner", TargetID: "mcp-remote", Scopes: []string{"files:read"}})
	g.clearSession("c1")
	if out := call(kctx); out != "ok" || up.calls != 2 {
		t.Fatalf("remembered: %q calls=%d", out, up.calls)
	}
	g.clearSession("c1")
	res, _ := g.guardedCall(kctx, "c1", nil, "write_file", map[string]any{}, "", json.RawMessage(`{}`))
	if !res.IsError || !strings.Contains(mustText(res, nil), "not granted") {
		t.Fatalf("a scope outside the remembered ones must still ask: %q", mustText(res, nil))
	}
	if !g.canRemember(kctx) {
		t.Fatal("a remember-mode target must offer always")
	}
	g.access.Consent = store.ConsentAsk
	if g.canRemember(kctx) {
		t.Fatal("an ask-every-time target must not offer always")
	}

	// "always" merges into what is remembered, under the agent's id
	st.DeleteRemembered(ctx, "planner", "mcp-remote")
	g.rememberAlways(kctx, []string{"files:write"}, "test")
	g.rememberAlways(kctx, []string{"files:read"}, "test")
	p, err := st.GetRemembered(ctx, "planner", "mcp-remote")
	if err != nil || len(p.Scopes) != 2 {
		t.Fatalf("remembered = %+v %v", p, err)
	}
	if _, err := st.GetRemembered(ctx, "akey_p", "mcp-remote"); err == nil {
		t.Fatal("an agent's always must not be keyed by its key")
	}
}
