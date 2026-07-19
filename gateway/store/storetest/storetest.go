// Package storetest is the conformance suite every store.Store implementation must pass.
// It exercises the documented contract of each method group — not one implementation's
// incidental behavior — so a new backend (files, SQL, …) proves itself by running Run
// against a factory that returns a fresh, empty store.
package storetest

import (
	"context"
	"errors"
	"testing"

	"delegent.dev/gateway/store"
)

// Run drives the full conformance suite. open must return a fresh, EMPTY store for each call;
// the suite owns its lifecycle and calls Close.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	t.Run("Sessions", func(t *testing.T) { testSessions(t, open(t)) })
	t.Run("Spend", func(t *testing.T) { testSpend(t, open(t)) })
	t.Run("Receipts", func(t *testing.T) { testReceipts(t, open(t)) })
	t.Run("Events", func(t *testing.T) { testEvents(t, open(t)) })
	t.Run("ConsentRequests", func(t *testing.T) { testConsentRequests(t, open(t)) })
	t.Run("TargetsAdaptersAdvisors", func(t *testing.T) { testTargets(t, open(t)) })
	t.Run("UsersEntitlements", func(t *testing.T) { testUsersEntitlements(t, open(t)) })
	t.Run("AgentKeys", func(t *testing.T) { testAgentKeys(t, open(t)) })
	t.Run("Channels", func(t *testing.T) { testChannels(t, open(t)) })
	t.Run("OAuth", func(t *testing.T) { testOAuth(t, open(t)) })
	t.Run("Secrets", func(t *testing.T) { testSecrets(t, open(t)) })
}

func ctx() context.Context { return context.Background() }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func wantNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func testSessions(t *testing.T, s store.Store) {
	defer s.Close()
	_, err := s.GetSession(ctx(), "sess_missing")
	wantNotFound(t, err)

	a := &store.Session{Handle: "sess_a", Principal: "usr_1", Chain: []store.SlipRow{{Canonical: []byte(`{"v":1}`), Sig: "aa"}}, Scopes: []string{"read"}, CreatedAt: 100}
	b := &store.Session{Handle: "sess_b", Principal: "usr_1", CreatedAt: 200}
	c := &store.Session{Handle: "sess_c", Principal: "usr_2", CreatedAt: 300}
	for _, x := range []*store.Session{a, b, c} {
		must(t, s.PutSession(ctx(), x))
	}

	got, err := s.GetSession(ctx(), "sess_a")
	must(t, err)
	if got.Principal != "usr_1" || len(got.Chain) != 1 || string(got.Chain[0].Canonical) != `{"v":1}` {
		t.Fatalf("session round-trip mangled: %+v", got)
	}
	list, err := s.ListSessions(ctx(), "usr_1")
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("ListSessions(usr_1) = %d sessions, want 2", len(list))
	}
}

func testSpend(t *testing.T, s store.Store) {
	defer s.Close()
	must(t, s.PutSession(ctx(), &store.Session{Handle: "sess_b", Principal: "usr_1", HasBudget: true, BudgetTotalC: 1000, BudgetRemainingC: 1000}))

	rem, err := s.Spend(ctx(), "sess_b", 400, store.LedgerEntry{Amount: 400, Tool: "x"})
	must(t, err)
	if rem != 600 {
		t.Fatalf("remaining after 400 spend = %d, want 600", rem)
	}
	if _, err := s.Spend(ctx(), "sess_b", 700, store.LedgerEntry{Amount: 700}); !errors.Is(err, store.ErrInsufficientBudget) {
		t.Fatalf("overdraw: want ErrInsufficientBudget, got %v", err)
	}
	// a failed spend must not debit
	rem, err = s.Spend(ctx(), "sess_b", 600, store.LedgerEntry{Amount: 600})
	must(t, err)
	if rem != 0 {
		t.Fatalf("remaining = %d, want 0", rem)
	}
	// no budget configured = nothing to debit, never an error
	must(t, s.PutSession(ctx(), &store.Session{Handle: "sess_free", Principal: "usr_1"}))
	if _, err := s.Spend(ctx(), "sess_free", 10_000, store.LedgerEntry{Amount: 10_000}); err != nil {
		t.Fatalf("spend on budget-less session: %v", err)
	}
	if _, err := s.Spend(ctx(), "sess_missing", 1, store.LedgerEntry{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("spend on missing session: want ErrNotFound, got %v", err)
	}
}

func testReceipts(t *testing.T, s store.Store) {
	defer s.Close()
	h, err := s.LastReceiptHash(ctx(), "usr_1")
	must(t, err)
	if h != "" {
		t.Fatalf("LastReceiptHash on empty store = %q, want \"\"", h)
	}

	rs := []*store.Receipt{
		{ID: "rcp_1", Principal: "usr_1", Handle: "sess_a", Tool: "read_file", Decision: "grant", Scopes: []string{"read"}, CreatedAt: 100, PrevHash: "", Hash: "h1", Sig: "s1"},
		{ID: "rcp_2", Principal: "usr_2", Handle: "sess_c", Tool: "send_mail", Decision: "deny", CreatedAt: 200, Hash: "x1"},
		{ID: "rcp_3", Principal: "usr_1", Handle: "sess_a", Tool: "write_file", Decision: "grant", CreatedAt: 300, PrevHash: "h1", Hash: "h2", Sig: "s2"},
	}
	for _, r := range rs {
		must(t, s.AppendReceipt(ctx(), r))
	}

	h, err = s.LastReceiptHash(ctx(), "usr_1")
	must(t, err)
	if h != "h2" {
		t.Fatalf("LastReceiptHash(usr_1) = %q, want h2", h)
	}

	list, err := s.ListReceipts(ctx(), store.ReceiptFilter{Principal: "usr_1"})
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("ListReceipts(usr_1) = %d, want 2", len(list))
	}
	// per-principal chain order must be preserved (PrevHash linkage is order)
	if list[0].ID != "rcp_1" || list[1].ID != "rcp_3" {
		t.Fatalf("principal chain order broken: %s, %s", list[0].ID, list[1].ID)
	}
	list, err = s.ListReceipts(ctx(), store.ReceiptFilter{Handle: "sess_c"})
	must(t, err)
	if len(list) != 1 || list[0].ID != "rcp_2" {
		t.Fatalf("ListReceipts(handle sess_c) wrong: %+v", list)
	}
	list, err = s.ListReceipts(ctx(), store.ReceiptFilter{Principal: "usr_1", Limit: 1})
	must(t, err)
	if len(list) != 1 || list[0].ID != "rcp_3" {
		t.Fatalf("Limit=1 must keep the most recent receipt, got %+v", list[0])
	}
}

func testEvents(t *testing.T, s store.Store) {
	defer s.Close()
	es := []*store.Event{
		{ID: "evt_1", Type: store.EventConnection, UserID: "usr_1", KeyName: "ci", CreatedAt: 100},
		{ID: "evt_2", Type: store.EventToolCall, UserID: "usr_1", KeyName: "ci", TargetID: "tgt_1", Tool: "read_file", CreatedAt: 200},
		{ID: "evt_3", Type: store.EventToolCall, UserID: "usr_2", KeyName: "dev", Tool: "send_mail", Decision: "deny", CreatedAt: 300},
	}
	for _, e := range es {
		must(t, s.AppendEvent(ctx(), e))
	}

	list, err := s.ListEvents(ctx(), store.EventFilter{KeyName: "ci"})
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("ListEvents(ci) = %d, want 2", len(list))
	}
	list, err = s.ListEvents(ctx(), store.EventFilter{Type: store.EventToolCall, Tool: "send_mail"})
	must(t, err)
	if len(list) != 1 || list[0].ID != "evt_3" {
		t.Fatalf("filtered events wrong: %+v", list)
	}
	list, err = s.ListEvents(ctx(), store.EventFilter{Limit: 1})
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("Limit=1 returned %d events", len(list))
	}
}

func testConsentRequests(t *testing.T, s store.Store) {
	defer s.Close()
	_, err := s.GetConsentRequest(ctx(), "creq_missing")
	wantNotFound(t, err)

	old := &store.ConsentRequest{ID: "creq_old", Principal: "usr_1", TargetID: "tgt_1", Status: "pending", Scopes: []string{"read"}, CreatedAt: 100, ExpiresAt: 500}
	live := &store.ConsentRequest{ID: "creq_live", Principal: "usr_1", TargetID: "tgt_1", Status: "pending", Headline: "Read files", Intent: "sync", CreatedAt: 200, ExpiresAt: 10_000}
	done := &store.ConsentRequest{ID: "creq_done", Principal: "usr_1", TargetID: "tgt_1", Status: "approved", DecidedScopes: []string{"read"}, CreatedAt: 300, ResolvedAt: 400}
	for _, r := range []*store.ConsentRequest{old, live, done} {
		must(t, s.PutConsentRequest(ctx(), r))
	}

	n, err := s.ExpireStaleConsentRequests(ctx(), 1000)
	must(t, err)
	if n != 1 {
		t.Fatalf("expired %d rows, want 1", n)
	}
	got, err := s.GetConsentRequest(ctx(), "creq_old")
	must(t, err)
	if got.Status != "expired" || got.ResolvedAt == 0 {
		t.Fatalf("stale row not expired: %+v", got)
	}

	pending, err := s.ListConsentRequests(ctx(), "usr_1", false)
	must(t, err)
	if len(pending) != 1 || pending[0].ID != "creq_live" {
		t.Fatalf("pending-only list wrong: %+v", pending)
	}
	all, err := s.ListConsentRequests(ctx(), "usr_1", true)
	must(t, err)
	if len(all) != 3 || all[0].ID != "creq_live" {
		t.Fatalf("full list must be pending-first, got %+v", all)
	}
	// upsert by id
	live.Status = "approved"
	live.ResolvedAt = 900
	must(t, s.PutConsentRequest(ctx(), live))
	got, err = s.GetConsentRequest(ctx(), "creq_live")
	must(t, err)
	if got.Status != "approved" {
		t.Fatalf("upsert did not stick: %+v", got)
	}
}

func testTargets(t *testing.T, s store.Store) {
	defer s.Close()
	_, err := s.GetTarget(ctx(), "tgt_missing")
	wantNotFound(t, err)

	tg := &store.Target{ID: "tgt_1", Name: "github", Kind: "mcp", Endpoint: "https://api.example/mcp", CredentialRef: "cred:tgt_1", CredentialKind: "static_bearer", AdapterID: "adp_1", Owner: "usr_1", Enabled: true}
	must(t, s.PutTarget(ctx(), tg))
	must(t, s.PutTarget(ctx(), &store.Target{ID: "tgt_2", Name: "demo", Kind: "rest", Owner: "usr_1"}))

	got, err := s.GetTarget(ctx(), "tgt_1")
	must(t, err)
	if got.Name != "github" || !got.Enabled || got.CredentialKind != "static_bearer" {
		t.Fatalf("target round-trip mangled: %+v", got)
	}
	list, err := s.ListTargets(ctx())
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("ListTargets = %d, want 2", len(list))
	}

	must(t, s.PutAdapter(ctx(), &store.AdapterDoc{ID: "adp_1", Name: "github", Doc: []byte(`{"tools":[]}`)}))
	ad, err := s.GetAdapter(ctx(), "adp_1")
	must(t, err)
	if string(ad.Doc) != `{"tools":[]}` {
		t.Fatalf("adapter doc mangled: %s", ad.Doc)
	}
	must(t, s.PutAdvisor(ctx(), &store.AdvisorDoc{ID: "adv_1", Name: "github", Doc: []byte(`{"rules":[]}`)}))
	av, err := s.GetAdvisor(ctx(), "adv_1")
	must(t, err)
	if string(av.Doc) != `{"rules":[]}` {
		t.Fatalf("advisor doc mangled: %s", av.Doc)
	}
}

func testUsersEntitlements(t *testing.T, s store.Store) {
	defer s.Close()
	u := &store.User{ID: "usr_1", ExternalID: "ext_abc", Email: "op@example.com", Name: "Op", Pubkey: "aabb", SealedKey: []byte{1, 2, 3}, CreatedAt: 100}
	must(t, s.PutUser(ctx(), u))

	got, err := s.GetUser(ctx(), "usr_1")
	must(t, err)
	if got.Email != "op@example.com" || string(got.SealedKey) != string([]byte{1, 2, 3}) {
		t.Fatalf("user round-trip mangled: %+v", got)
	}
	got, err = s.GetUserByExternal(ctx(), "ext_abc")
	must(t, err)
	if got.ID != "usr_1" {
		t.Fatalf("GetUserByExternal = %+v", got)
	}
	_, err = s.GetUserByExternal(ctx(), "ext_nope")
	wantNotFound(t, err)
	list, err := s.ListUsers(ctx())
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("ListUsers = %d, want 1", len(list))
	}

	e := &store.Entitlement{UserID: "usr_1", TargetID: "tgt_1", Scopes: []string{"read", "write"}, Disabled: []string{"write"}}
	must(t, s.PutEntitlement(ctx(), e))
	ge, err := s.GetEntitlement(ctx(), "usr_1", "tgt_1")
	must(t, err)
	if len(ge.Scopes) != 2 || len(ge.Disabled) != 1 {
		t.Fatalf("entitlement round-trip mangled: %+v", ge)
	}
	byTarget, err := s.ListEntitlementsForTarget(ctx(), "tgt_1")
	must(t, err)
	byUser, err := s.ListEntitlementsForUser(ctx(), "usr_1")
	must(t, err)
	if len(byTarget) != 1 || len(byUser) != 1 {
		t.Fatalf("entitlement lists: byTarget=%d byUser=%d, want 1/1", len(byTarget), len(byUser))
	}
}

func testAgentKeys(t *testing.T, s store.Store) {
	defer s.Close()
	k := &store.AgentKey{ID: "akey_1", UserID: "usr_1", Hash: []byte{0xde, 0xad}, Prefix: "dgk_ab", Name: "ci", CreatedAt: 100}
	must(t, s.PutAgentKey(ctx(), k))
	if err := s.PutAgentKey(ctx(), k); err == nil {
		t.Fatalf("keys are create-only: duplicate id must error")
	}

	got, err := s.GetAgentKeyByHash(ctx(), []byte{0xde, 0xad})
	must(t, err)
	if got.ID != "akey_1" {
		t.Fatalf("GetAgentKeyByHash = %+v", got)
	}
	must(t, s.TouchAgentKey(ctx(), "akey_1", 500))
	must(t, s.SetAgentKeyConsentChannels(ctx(), "akey_1", []string{"widget", "console"}))
	got, err = s.GetAgentKey(ctx(), "akey_1")
	must(t, err)
	if got.LastUsedAt != 500 || len(got.ConsentChannels) != 2 {
		t.Fatalf("touch/channels not applied: %+v", got)
	}
	must(t, s.RevokeAgentKey(ctx(), "akey_1", 900))
	got, err = s.GetAgentKey(ctx(), "akey_1")
	must(t, err)
	if got.RevokedAt != 900 {
		t.Fatalf("revoke not applied: %+v", got)
	}
	list, err := s.ListAgentKeys(ctx(), "usr_1")
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("ListAgentKeys = %d, want 1", len(list))
	}
}

func testChannels(t *testing.T, s store.Store) {
	defer s.Close()
	c := &store.ChannelConnection{UserID: "usr_1", Kind: "telegram", Address: "12345", Label: "@op", CreatedAt: 100}
	must(t, s.PutChannelConnection(ctx(), c))
	c.Address = "67890" // upsert on (user, kind)
	must(t, s.PutChannelConnection(ctx(), c))
	got, err := s.GetChannelConnection(ctx(), "usr_1", "telegram")
	must(t, err)
	if got.Address != "67890" {
		t.Fatalf("connection upsert did not stick: %+v", got)
	}
	list, err := s.ListChannelConnections(ctx(), "usr_1")
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("ListChannelConnections = %d, want 1", len(list))
	}
	must(t, s.DeleteChannelConnection(ctx(), "usr_1", "telegram"))
	_, err = s.GetChannelConnection(ctx(), "usr_1", "telegram")
	wantNotFound(t, err)

	// link tokens: single-use, TTL'd
	must(t, s.PutChannelLinkToken(ctx(), &store.ChannelLinkToken{Token: "tok_live", UserID: "usr_1", Kind: "telegram", ExpiresAt: 10_000, CreatedAt: 100}))
	must(t, s.PutChannelLinkToken(ctx(), &store.ChannelLinkToken{Token: "tok_stale", UserID: "usr_1", Kind: "telegram", ExpiresAt: 500, CreatedAt: 100}))
	_, err = s.TakeChannelLinkToken(ctx(), "tok_stale", 1000)
	wantNotFound(t, err)
	tok, err := s.TakeChannelLinkToken(ctx(), "tok_live", 1000)
	must(t, err)
	if tok.UserID != "usr_1" {
		t.Fatalf("token mangled: %+v", tok)
	}
	_, err = s.TakeChannelLinkToken(ctx(), "tok_live", 1000)
	wantNotFound(t, err) // consumed

	// settings: one row per kind
	must(t, s.PutChannelSetting(ctx(), &store.ChannelSetting{Kind: "telegram", Settings: []byte(`{"bot_username":"door_bot"}`), UpdatedAt: 100}))
	st, err := s.GetChannelSetting(ctx(), "telegram")
	must(t, err)
	if string(st.Settings) != `{"bot_username":"door_bot"}` {
		t.Fatalf("setting mangled: %+v", st)
	}
	must(t, s.DeleteChannelSetting(ctx(), "telegram"))
	_, err = s.GetChannelSetting(ctx(), "telegram")
	wantNotFound(t, err)
}

func testOAuth(t *testing.T, s store.Store) {
	defer s.Close()
	must(t, s.PutOAuthClient(ctx(), &store.OAuthClient{TargetID: "tgt_1", AuthEndpoint: "https://v/auth", TokenEndpoint: "https://v/token", ClientID: "cid", Scopes: "read write", RedirectURI: "http://127.0.0.1/cb"}))
	oc, err := s.GetOAuthClient(ctx(), "tgt_1")
	must(t, err)
	if oc.ClientID != "cid" {
		t.Fatalf("oauth client mangled: %+v", oc)
	}

	// flows are single-use
	must(t, s.PutOAuthFlow(ctx(), &store.OAuthFlow{State: "st_1", TargetID: "tgt_1", CodeVerifier: "ver", CreatedAt: 100}))
	fl, err := s.TakeOAuthFlow(ctx(), "st_1")
	must(t, err)
	if fl.CodeVerifier != "ver" {
		t.Fatalf("flow mangled: %+v", fl)
	}
	_, err = s.TakeOAuthFlow(ctx(), "st_1")
	wantNotFound(t, err)

	// pending: Get does not consume, Take does, ExpireStalePending reaps blobs too
	must(t, s.PutSecret(ctx(), "oauth:stale:token", []byte("sealed")))
	must(t, s.PutOAuthPending(ctx(), &store.OAuthPending{State: "pnd_live", ClientID: "cid", CreatedAt: 1000}))
	must(t, s.PutOAuthPending(ctx(), &store.OAuthPending{State: "pnd_stale", ClientID: "cid", TokenRef: "oauth:stale:token", CreatedAt: 10}))

	p, err := s.GetOAuthPending(ctx(), "pnd_live")
	must(t, err)
	if p.ClientID != "cid" {
		t.Fatalf("pending mangled: %+v", p)
	}
	if _, err = s.GetOAuthPending(ctx(), "pnd_live"); err != nil {
		t.Fatalf("Get must not consume: %v", err)
	}

	n, err := s.ExpireStalePending(ctx(), 500)
	must(t, err)
	if n != 1 {
		t.Fatalf("ExpireStalePending swept %d, want 1", n)
	}
	_, err = s.GetOAuthPending(ctx(), "pnd_stale")
	wantNotFound(t, err)
	_, err = s.GetSecret(ctx(), "oauth:stale:token")
	wantNotFound(t, err) // associated sealed blob reaped with the row

	_, err = s.TakeOAuthPending(ctx(), "pnd_live")
	must(t, err)
	_, err = s.GetOAuthPending(ctx(), "pnd_live")
	wantNotFound(t, err) // consumed
}

func testSecrets(t *testing.T, s store.Store) {
	defer s.Close()
	_, err := s.GetSecret(ctx(), "cred:missing")
	wantNotFound(t, err)
	must(t, s.PutSecret(ctx(), "cred:tgt_1", []byte{0x01, 0x02}))
	must(t, s.PutSecret(ctx(), "cred:tgt_1", []byte{0x03})) // overwrite
	got, err := s.GetSecret(ctx(), "cred:tgt_1")
	must(t, err)
	if len(got) != 1 || got[0] != 0x03 {
		t.Fatalf("secret round-trip mangled: %v", got)
	}
	must(t, s.DeleteSecret(ctx(), "cred:tgt_1"))
	_, err = s.GetSecret(ctx(), "cred:tgt_1")
	wantNotFound(t, err)
	must(t, s.DeleteSecret(ctx(), "cred:tgt_1")) // idempotent
}
