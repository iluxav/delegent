package telegram

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// The Manager is the DB-configured runtime for the telegram channel: Reload() reads the
// channel_settings row + the sealed bot token and (re)starts the poller/notifier; removing the
// configuration stops them. It stands in as the gateway's ConsentNotifier from boot, so wiring
// never changes — only its inner state does.

func managerFixture(t *testing.T) (*store.MemStore, *secretstore.DB, *fakeBotAPI, *Manager) {
	t.Helper()
	st := store.NewMemStore()
	sealer, err := keyring.NewAESSealer([]byte("delegent-dev-master-key-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	secrets := secretstore.NewDB(st, sealer)
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	t.Cleanup(ts.Close)
	m := NewManager(ManagerOptions{
		Store: st, Secrets: secrets, ConsoleURL: "https://console.example",
		Now: func() int64 { return 1000 }, BaseURL: ts.URL, HTTPClient: ts.Client(),
	})
	t.Cleanup(m.Stop)
	return st, secrets, fake, m
}

func configure(t *testing.T, st *store.MemStore, secrets *secretstore.DB) {
	t.Helper()
	ctx := context.Background()
	if err := secrets.Put(ctx, "channel:telegram:token", "bot-token-123"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutChannelSetting(ctx, &store.ChannelSetting{
		Kind: "telegram", Settings: []byte(`{"bot_username":"delegent_bot"}`), UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestManagerUnconfiguredIsInert(t *testing.T) {
	_, _, fake, m := managerFixture(t)
	if err := m.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := m.BotUsername(); ok {
		t.Fatal("BotUsername should report unconfigured")
	}
	// notifying while unconfigured is a silent no-op
	m.ConsentParked(&store.ConsentRequest{ID: "creq_1", Principal: "usr_op", Scopes: []string{"x"}})
	time.Sleep(100 * time.Millisecond)
	if got := fake.sentBodies(); len(got) != 0 {
		t.Fatalf("unconfigured manager sent: %+v", got)
	}
}

func TestManagerReloadConfigures(t *testing.T) {
	st, secrets, fake, m := managerFixture(t)
	configure(t, st, secrets)
	ctx := context.Background()
	_ = st.PutChannelConnection(ctx, &store.ChannelConnection{UserID: "usr_op", Kind: "telegram", Address: "555"})

	if err := m.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if u, ok := m.BotUsername(); !ok || u != "delegent_bot" {
		t.Fatalf("BotUsername = %q ok=%v", u, ok)
	}
	// notifier is live
	m.ConsentParked(&store.ConsentRequest{ID: "creq_1", Principal: "usr_op", Scopes: []string{"files:write"}})
	if sent := waitSent(t, fake, 1); len(sent) != 1 || sent[0]["chat_id"] != "555" {
		t.Fatalf("notice not sent: %+v", sent)
	}
	// poller is live (getUpdates being hit)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		calls := fake.upCalls
		fake.mu.Unlock()
		if calls > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("poller never polled")
}

func TestManagerReloadAfterRemovalStops(t *testing.T) {
	st, secrets, fake, m := managerFixture(t)
	configure(t, st, secrets)
	ctx := context.Background()
	if err := m.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := m.BotUsername(); !ok {
		t.Fatal("should be configured")
	}

	_ = st.DeleteChannelSetting(ctx, "telegram")
	if err := m.Reload(ctx); err != nil {
		t.Fatalf("reload after removal: %v", err)
	}
	if _, ok := m.BotUsername(); ok {
		t.Fatal("BotUsername should report unconfigured after removal")
	}
	// the poller stops: after a settle, the getUpdates count stays flat
	time.Sleep(100 * time.Millisecond)
	fake.mu.Lock()
	before := fake.upCalls
	fake.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	fake.mu.Lock()
	after := fake.upCalls
	fake.mu.Unlock()
	if after != before {
		t.Fatalf("poller still running after removal: %d -> %d", before, after)
	}
	// and notifications are inert again
	m.ConsentParked(&store.ConsentRequest{ID: "creq_2", Principal: "usr_op", Scopes: []string{"x"}})
	time.Sleep(100 * time.Millisecond)
	if got := fake.sentBodies(); len(got) != 0 {
		t.Fatalf("removed manager sent: %+v", got)
	}
}
