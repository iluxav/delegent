package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"delegent.dev/gateway/store"
	"delegent.dev/gateway/store/storetest"
)

func openJSON(t *testing.T, dir string) *store.JSONFileStore {
	t.Helper()
	s, err := store.NewJSONFileStore(dir)
	if err != nil {
		t.Fatalf("NewJSONFileStore(%s): %v", dir, err)
	}
	return s
}

func TestJSONFileStore_Conformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return openJSON(t, t.TempDir()) })
}

// TestJSONFileStore_Reopen is the point of the implementation: durable state written through
// one store must be visible through a second store opened on the same directory.
func TestJSONFileStore_Reopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openJSON(t, dir)

	if err := s.PutUser(ctx, &store.User{ID: "usr_1", Email: "op@example.com", Pubkey: "aabb", SealedKey: []byte{9}, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutTarget(ctx, &store.Target{ID: "tgt_1", Name: "github", Kind: "mcp", Owner: "usr_1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdapter(ctx, &store.AdapterDoc{ID: "adp_1", Name: "github", Doc: []byte(`{"tools":[]}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdvisor(ctx, &store.AdvisorDoc{ID: "adv_1", Name: "github", Doc: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEntitlement(ctx, &store.Entitlement{UserID: "usr_1", TargetID: "tgt_1", Scopes: []string{"read", "write"}, Disabled: []string{"write"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAgentKey(ctx, &store.AgentKey{ID: "akey_1", UserID: "usr_1", Hash: []byte{0xde, 0xad}, Prefix: "dgk_ab", Name: "ci", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAgentKeyConsentChannels(ctx, "akey_1", []string{"telegram", "console"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSecret(ctx, "cred:tgt_1", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutConsentRequest(ctx, &store.ConsentRequest{ID: "creq_1", Principal: "usr_1", TargetID: "tgt_1", Status: "pending", Headline: "Read files", CreatedAt: 1, ExpiresAt: 1 << 60}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutChannelConnection(ctx, &store.ChannelConnection{UserID: "usr_1", Kind: "telegram", Address: "123", Label: "@op", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutChannelSetting(ctx, &store.ChannelSetting{Kind: "telegram", Settings: []byte(`{"bot_username":"b"}`), UpdatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthClient(ctx, &store.OAuthClient{TargetID: "tgt_1", ClientID: "cid"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthPending(ctx, &store.OAuthPending{State: "pnd_1", ClientID: "cid", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*store.Receipt{
		{ID: "rcp_1", Principal: "usr_1", Tool: "read_file", Decision: "grant", CreatedAt: 100, Hash: "h1"},
		{ID: "rcp_2", Principal: "usr_2", Tool: "send_mail", Decision: "deny", CreatedAt: 200, Hash: "x1"},
		{ID: "rcp_3", Principal: "usr_1", Tool: "write_file", Decision: "grant", CreatedAt: 300, PrevHash: "h1", Hash: "h2"},
	} {
		if err := s.AppendReceipt(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AppendEvent(ctx, &store.Event{ID: "evt_1", Type: store.EventToolCall, UserID: "usr_1", KeyName: "ci", Tool: "read_file", CreatedAt: 100}); err != nil {
		t.Fatal(err)
	}
	// ephemeral rows must NOT survive a reopen
	if err := s.PutSession(ctx, &store.Session{Handle: "sess_a", Principal: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutOAuthFlow(ctx, &store.OAuthFlow{State: "st_1", CodeVerifier: "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	r := openJSON(t, dir)
	defer r.Close()

	u, err := r.GetUser(ctx, "usr_1")
	if err != nil || u.Email != "op@example.com" || string(u.SealedKey) != string([]byte{9}) {
		t.Fatalf("user lost or mangled: %+v, %v", u, err)
	}
	tg, err := r.GetTarget(ctx, "tgt_1")
	if err != nil || tg.Name != "github" || !tg.Enabled {
		t.Fatalf("target lost or mangled: %+v, %v", tg, err)
	}
	if _, err := r.GetAdapter(ctx, "adp_1"); err != nil {
		t.Fatalf("adapter lost: %v", err)
	}
	if _, err := r.GetAdvisor(ctx, "adv_1"); err != nil {
		t.Fatalf("advisor lost: %v", err)
	}
	e, err := r.GetEntitlement(ctx, "usr_1", "tgt_1")
	if err != nil || len(e.Scopes) != 2 || len(e.Disabled) != 1 {
		t.Fatalf("entitlement lost or mangled: %+v, %v", e, err)
	}
	k, err := r.GetAgentKeyByHash(ctx, []byte{0xde, 0xad})
	if err != nil || k.ID != "akey_1" || len(k.ConsentChannels) != 2 {
		t.Fatalf("agent key lost or mangled: %+v, %v", k, err)
	}
	sec, err := r.GetSecret(ctx, "cred:tgt_1")
	if err != nil || string(sec) != string([]byte{1, 2, 3}) {
		t.Fatalf("secret lost or mangled: %v, %v", sec, err)
	}
	cr, err := r.GetConsentRequest(ctx, "creq_1")
	if err != nil || cr.Status != "pending" || cr.Headline != "Read files" {
		t.Fatalf("consent request lost or mangled: %+v, %v", cr, err)
	}
	if _, err := r.GetChannelConnection(ctx, "usr_1", "telegram"); err != nil {
		t.Fatalf("channel connection lost: %v", err)
	}
	if _, err := r.GetChannelSetting(ctx, "telegram"); err != nil {
		t.Fatalf("channel setting lost: %v", err)
	}
	if _, err := r.GetOAuthClient(ctx, "tgt_1"); err != nil {
		t.Fatalf("oauth client lost: %v", err)
	}
	if _, err := r.GetOAuthPending(ctx, "pnd_1"); err != nil {
		t.Fatalf("oauth pending lost: %v", err)
	}

	h, err := r.LastReceiptHash(ctx, "usr_1")
	if err != nil || h != "h2" {
		t.Fatalf("receipt chain head = %q, %v; want h2", h, err)
	}
	rl, err := r.ListReceipts(ctx, store.ReceiptFilter{Principal: "usr_1"})
	if err != nil || len(rl) != 2 || rl[0].ID != "rcp_1" || rl[1].ID != "rcp_3" {
		t.Fatalf("receipt chain order lost: %+v, %v", rl, err)
	}
	ev, err := r.ListEvents(ctx, store.EventFilter{KeyName: "ci"})
	if err != nil || len(ev) != 1 || ev[0].Tool != "read_file" {
		t.Fatalf("events lost: %+v, %v", ev, err)
	}

	if _, err := r.GetSession(ctx, "sess_a"); err == nil {
		t.Fatal("sessions are ephemeral: must not survive reopen")
	}
	if _, err := r.TakeOAuthFlow(ctx, "st_1"); err == nil {
		t.Fatal("oauth flows are ephemeral: must not survive reopen")
	}
}

// Mutations after a reopen must keep persisting (the reopened store is not read-only).
func TestJSONFileStore_MutateAfterReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openJSON(t, dir)
	if err := s.PutTarget(ctx, &store.Target{ID: "tgt_1", Name: "one", Owner: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s = openJSON(t, dir)
	if err := s.PutTarget(ctx, &store.Target{ID: "tgt_1", Name: "renamed", Owner: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendReceipt(ctx, &store.Receipt{ID: "rcp_9", Principal: "usr_1", Hash: "h9", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s = openJSON(t, dir)
	defer s.Close()
	tg, err := s.GetTarget(ctx, "tgt_1")
	if err != nil || tg.Name != "renamed" {
		t.Fatalf("post-reopen mutation lost: %+v, %v", tg, err)
	}
	if h, _ := s.LastReceiptHash(ctx, "usr_1"); h != "h9" {
		t.Fatalf("post-reopen receipt lost: head %q", h)
	}
}

// The on-disk files are plain, diffable JSON — the formats double as the export format.
func TestJSONFileStore_FilesArePlainJSON(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openJSON(t, dir)
	defer s.Close()
	if err := s.PutTarget(ctx, &store.Target{ID: "tgt_1", Name: "github", Owner: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendReceipt(ctx, &store.Receipt{ID: "rcp_1", Principal: "root:alice", Hash: "h1", CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "targets.json"))
	if err != nil {
		t.Fatalf("targets.json not written: %v", err)
	}
	var targets []store.Target
	if err := json.Unmarshal(raw, &targets); err != nil || len(targets) != 1 || targets[0].ID != "tgt_1" {
		t.Fatalf("targets.json not a plain JSON array of targets: %v, %s", err, raw)
	}

	entries, err := os.ReadDir(filepath.Join(dir, "receipts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("receipts/ dir: %v, %d entries", err, len(entries))
	}
	line, err := os.ReadFile(filepath.Join(dir, "receipts", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var rec store.Receipt
	if err := json.Unmarshal(line, &rec); err != nil || rec.ID != "rcp_1" {
		t.Fatalf("receipt line not plain JSON: %v, %s", err, line)
	}
}
