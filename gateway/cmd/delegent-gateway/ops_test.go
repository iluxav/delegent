package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"delegent.dev/gateway"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
	"delegent.dev/gateway/telegram"
)

// opsFixture builds an initialized instance (temp home, operator, one provisioned target
// with two classified tools + one unknown) and returns its env.
func opsFixture(t *testing.T) *env {
	t.Helper()
	t.Setenv("DELEGENT_MASTER_KEY", "")
	home := t.TempDir()
	if err := cmdInit([]string{"--home", home}); err != nil {
		t.Fatalf("init: %v", err)
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provision.CreateTarget(ctx, e.st, secretstore.NewDB(e.st, e.sealer), provision.CreateTargetInput{
		ID: "gh", Name: "github", Endpoint: "http://upstream.example/mcp", Owner: e.operator,
		Credential: "tok-upstream",
		Tools: []provision.ToolSpec{
			{Name: "read_file", Effect: "read", Scope: "files:read"},
			{Name: "send_mail", Effect: "external", Scope: "mail:send"},
			{Name: "mystery"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.AppendEvent(ctx, &store.Event{ID: "evt_1", Type: store.EventToolCall, UserID: e.operator,
		KeyName: "ci", TargetID: "gh", Tool: "read_file", Decision: "grant", CreatedAt: 100}); err != nil {
		t.Fatal(err)
	}
	return e
}

// runOpsSuite exercises every non-consent op identically against a backend.
func runOpsSuite(t *testing.T, o ops) {
	ctx := context.Background()

	// targets
	rows, err := o.ListTargets(ctx)
	if err != nil || len(rows) != 1 || rows[0].ID != "gh" || rows[0].Tools != 2 {
		t.Fatalf("ListTargets = %+v, %v (want 1 target, 2 classified tools)", rows, err)
	}
	det, err := o.TargetDetail(ctx, "gh")
	if err != nil {
		t.Fatal(err)
	}
	if len(det.Tools) != 2 || len(det.Entitlement.Scopes) != 3 { // mcp:connect + 2
		t.Fatalf("detail: tools=%d scopes=%v", len(det.Tools), det.Entitlement.Scopes)
	}
	if _, err := o.TargetDetail(ctx, "nope"); err == nil {
		t.Fatal("missing target must error")
	}

	// policy edit: reclassify mystery, flip send_mail off (unknown)
	tools := []provision.ToolSpec{
		{Name: "read_file", Effect: "read", Scope: "files:read"},
		{Name: "send_mail", Effect: "unknown"},
		{Name: "mystery", Effect: "write", Scope: "files:write"},
	}
	if err := o.PutPolicy(ctx, "gh", "", tools); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	det, err = o.TargetDetail(ctx, "gh")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]provision.ToolSpec{}
	for _, tl := range det.Tools {
		byName[tl.Name] = tl
	}
	if byName["mystery"].Scope != "files:write" {
		t.Fatalf("mystery not reclassified: %+v", det.Tools)
	}
	if _, ok := byName["send_mail"]; ok {
		t.Fatalf("send_mail flipped unknown must leave the adapter rules: %+v", det.Tools)
	}
	// entitlement UNION: mail:send survives (never narrowed), files:write added
	scopes := strings.Join(det.Entitlement.Scopes, ",")
	if !strings.Contains(scopes, "mail:send") || !strings.Contains(scopes, "files:write") {
		t.Fatalf("entitlement union broken: %v", det.Entitlement.Scopes)
	}

	// scope opt-out
	ent, err := o.SetDisabled(ctx, "gh", []string{"mail:send", "not-held"})
	if err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}
	if len(ent.Disabled) != 1 || ent.Disabled[0] != "mail:send" {
		t.Fatalf("disabled = %v (clamp to held scopes)", ent.Disabled)
	}
	if strings.Contains(strings.Join(ent.Effective, ","), "mail:send") {
		t.Fatalf("effective must exclude opted-out scope: %v", ent.Effective)
	}

	// target enable/disable
	if err := o.SetTargetEnabled(ctx, "gh", false); err != nil {
		t.Fatal(err)
	}
	rows, _ = o.ListTargets(ctx)
	if rows[0].Enabled {
		t.Fatal("disable did not stick")
	}
	if err := o.SetTargetEnabled(ctx, "gh", true); err != nil {
		t.Fatal(err)
	}

	// keys: mint, roll (same name, old revoked, new plaintext), revoke
	row, plain, err := o.MintKey(ctx, "laptop")
	if err != nil || !strings.HasPrefix(plain, "dgk_") {
		t.Fatalf("MintKey: %v %q", err, plain)
	}
	rolled, plain2, err := o.RollKey(ctx, row.ID)
	if err != nil {
		t.Fatalf("RollKey: %v", err)
	}
	if rolled.Name != "laptop" || plain2 == plain || rolled.ID == row.ID {
		t.Fatalf("roll must mint a fresh key under the same name: %+v", rolled)
	}
	keys, err := o.ListKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var oldRevoked, newActive bool
	for _, k := range keys {
		if k.ID == row.ID && k.RevokedAt != 0 {
			oldRevoked = true
		}
		if k.ID == rolled.ID && k.RevokedAt == 0 {
			newActive = true
		}
	}
	if !oldRevoked || !newActive {
		t.Fatalf("after roll: oldRevoked=%v newActive=%v keys=%+v", oldRevoked, newActive, keys)
	}
	if _, _, err := o.RollKey(ctx, row.ID); err == nil {
		t.Fatal("rolling a revoked key must refuse")
	}
	if err := o.RevokeKey(ctx, rolled.ID); err != nil {
		t.Fatal(err)
	}

	// events
	events, err := o.ListEvents(ctx, store.EventFilter{KeyName: "ci"})
	if err != nil || len(events) != 1 || events[0].Tool != "read_file" {
		t.Fatalf("ListEvents = %+v, %v", events, err)
	}

	// consents list (empty either way; resolution semantics differ per backend)
	if _, err := o.Consents(ctx); err != nil {
		t.Fatalf("Consents: %v", err)
	}
}

func TestOps_File(t *testing.T) {
	e := opsFixture(t)
	o := newFileOps(e)
	runOpsSuite(t, o)

	// file mode: consent features are offline-refused
	if _, err := o.Resolve(context.Background(), "x", true, nil, 0, 0); err != errOffline {
		t.Fatalf("Resolve offline = %v, want errOffline", err)
	}
	if _, _, err := o.StreamConsents(context.Background()); err != errOffline {
		t.Fatalf("StreamConsents offline = %v, want errOffline", err)
	}
}

func TestOps_API(t *testing.T) {
	e := opsFixture(t)
	registry := gateway.NewRegistry(e.st, e.sealer)
	tgm := telegram.NewManager(telegram.ManagerOptions{Store: e.st, Secrets: secretstore.NewDB(e.st, e.sealer), Resolver: registry})
	mux := http.NewServeMux()
	mountAdmin(mux, e, registry, tgm)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	o := newAPIOps(strings.TrimPrefix(srv.URL, "http://"), e.cfg.AdminToken, "live: test")
	runOpsSuite(t, o)

	// live extras: resolving an unknown ask is ok=false (not an error); the stream connects
	ok, err := o.Resolve(context.Background(), "creq_unknown", true, []string{"files:read"}, 30, 0)
	if err != nil || ok {
		t.Fatalf("Resolve unknown = %v ok=%v, want ok=false nil", err, ok)
	}
	ch, cancel, err := o.StreamConsents(context.Background())
	if err != nil {
		t.Fatalf("StreamConsents: %v", err)
	}
	cancel()
	for range ch { // must close promptly after cancel
	}

	// wrong token is refused
	bad := newAPIOps(strings.TrimPrefix(srv.URL, "http://"), "wrong", "live: bad")
	if _, err := bad.ListTargets(context.Background()); err == nil {
		t.Fatal("wrong admin token must be refused")
	}
}
