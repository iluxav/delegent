package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/store"
)

// ctxWithToken produces a context carrying ti in the auth TokenInfo slot — the same wiring
// RequireBearerToken does in production, so eventBase reads it back exactly as it would live.
func ctxWithToken(t *testing.T, ti *auth.TokenInfo) context.Context {
	t.Helper()
	var captured context.Context
	h := auth.RequireBearerToken(
		func(_ context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) { return ti, nil },
		&auth.RequireBearerTokenOptions{},
	)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { captured = r.Context() }))
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if captured == nil {
		t.Fatal("auth middleware rejected the token — no context captured")
	}
	return captured
}

// eventBase must lift the caller's key identity + resolved IP (and operating user) out of the
// TokenInfo Extra that makeVerifier threaded there.
func TestEventBaseFillsFromContext(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	ctx := ctxWithToken(t, &auth.TokenInfo{
		UserID: "root:alice", Expiration: time.Now().Add(time.Hour),
		Extra: map[string]any{"key_prefix": "dgk_abc", "key_name": "ci-bot", "remote_ip": "203.0.113.7"},
	})
	e := g.eventBase(ctx, "")
	if e.UserID != "root:alice" {
		t.Errorf("user = %q, want root:alice", e.UserID)
	}
	if e.KeyPrefix != "dgk_abc" || e.KeyName != "ci-bot" || e.RemoteIP != "203.0.113.7" {
		t.Errorf("key identity not lifted from ctx: %+v", e)
	}
	if e.TargetID != "mcp-remote" {
		t.Errorf("target = %q, want mcp-remote", e.TargetID)
	}
	if e.AgentName != "new agent connection" {
		t.Errorf("pre-session agent name = %q, want 'new agent connection'", e.AgentName)
	}
}

// emit persists an event best-effort into the wired store (asynchronously).
func TestEmitPersistsToStore(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	ctx := ctxWithToken(t, &auth.TokenInfo{
		UserID: "root:alice", Expiration: time.Now().Add(time.Hour),
		Extra: map[string]any{"key_prefix": "dgk_abc", "key_name": "ci-bot", "remote_ip": "203.0.113.7"},
	})
	ev := g.eventBase(ctx, "")
	ev.Type = store.EventConnection
	ev.ClientName = "claude-code"
	g.emit(ev)

	got := waitForEvents(t, g.st, store.EventFilter{UserID: "root:alice"}, 1)
	e := got[0]
	if e.Type != store.EventConnection || e.KeyName != "ci-bot" || e.RemoteIP != "203.0.113.7" || e.ClientName != "claude-code" {
		t.Fatalf("emitted event missing eventBase/type fields: %+v", e)
	}
}

// With the payloads flag OFF, params/result are never captured.
func TestCapPayloadFlagOff(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.logPayloads = false
	if got := g.capPayload(json.RawMessage(`{"path":"x"}`)); got != nil {
		t.Errorf("payloads off must drop params, got %s", got)
	}
	if got := g.capValue(map[string]any{"a": 1}); got != nil {
		t.Errorf("payloads off must drop result, got %s", got)
	}
}

// Oversized payloads are replaced with a {"_truncated":N} marker; small ones pass through.
func TestCapPayloadTruncates(t *testing.T) {
	g := scopeGateway(t, grantScopeConnection)
	g.logPayloads = true
	g.payloadMax = 10
	small := json.RawMessage(`{"a":1}`)
	if got := g.capPayload(small); string(got) != string(small) {
		t.Errorf("small payload should pass through, got %s", got)
	}
	big := json.RawMessage(`{"path":"a-very-long-value-way-over-ten-bytes"}`)
	got := g.capPayload(big)
	if !strings.Contains(string(got), `"_truncated"`) {
		t.Fatalf("oversized payload must be truncated, got %s", got)
	}
	var marker map[string]int
	if err := json.Unmarshal(got, &marker); err != nil || marker["_truncated"] != len(big) {
		t.Fatalf("truncation marker wrong: %s (err %v)", got, err)
	}
}

func waitForEvents(t *testing.T, st store.Store, f store.EventFilter, want int) []*store.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		evs, err := st.ListEvents(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) >= want {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d event(s) matching %+v (have %d)", want, f, len(evs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestToolResultTextSurfacesError(t *testing.T) {
	res := toolError("GitHub API returned 503 Service Unavailable")
	got := toolResultText(res)
	if got != "GitHub API returned 503 Service Unavailable" {
		t.Fatalf("toolResultText = %q", got)
	}
	// empty error result still yields a non-empty marker
	if toolResultText(&mcp.CallToolResult{IsError: true}) == "" {
		t.Fatal("empty error result must still produce a message")
	}
}
