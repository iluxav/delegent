package gateway

import (
	"context"
	"testing"

	core "delegent.dev/protocol"
	"delegent.dev/gateway/store"
)

// TestLoadConfig_CuratedSemanticsWin: an adapter doc carrying a `semantics` override alongside its
// enforcement `classify` rules is loaded such that (a) loadConfig returns the curated semantics map,
// and (b) enforcement is UNAFFECTED — core.Classify on the same adapter still classifies the tool
// (the display-only `semantics` key is ignored by the enforcement parse).
func TestLoadConfig_CuratedSemanticsWin(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemStore()

	// valid enforcement rule for list_repos + a display-only curated override for it.
	doc := `{"vendor":"gh","version":"1.0.0","classify":[` +
		`{"id":"tool.list_repos","match":{"method":"POST","path":"/mcp","body":{"method":"tools/call","params.name":"list_repos"}},"effect":"read","scopes":["repos:read"]}` +
		`],"default":{"effect":"unknown"},"semantics":{"list_repos":{"reversible":"irreversible","idempotent":"unknown","open_world":"unknown","cost":"unknown"}}}`
	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: "gh", Name: "gh", Doc: []byte(doc)}); err != nil {
		t.Fatalf("put adapter: %v", err)
	}
	if err := st.PutTarget(ctx, &store.Target{ID: "gh", Name: "gh", Kind: "mcp", Endpoint: "http://gh/mcp", AdapterID: "gh", Owner: "usr_op", Enabled: true}); err != nil {
		t.Fatalf("put target: %v", err)
	}
	target, _ := st.GetTarget(ctx, "gh")

	adapter, _, _, curated, err := loadConfig(ctx, st, target)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	// (a) curated semantics survive the load
	if got := curated["list_repos"].Reversible; got != "irreversible" {
		t.Fatalf("curated semantics not loaded: reversible=%q", got)
	}

	// (b) enforcement ignores the semantics key — the rule still classifies
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "list_repos"}}
	c := core.Classify(adapter, core.Request{Action: "POST", Resource: "/mcp", Body: body})
	if c.Unknown {
		t.Fatal("enforcement should classify list_repos; the semantics key must not break the parse")
	}
	if len(c.Scopes) != 1 || c.Scopes[0] != "repos:read" {
		t.Fatalf("expected scope repos:read, got %v", c.Scopes)
	}
}
