package telegram

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"delegent.dev/gateway/store"
)

func waitSent(t *testing.T, fake *fakeBotAPI, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := fake.sentBodies(); len(s) >= want {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fake.sentBodies()
}

func TestNotifierSendsToConnectedUser(t *testing.T) {
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()
	st := store.NewMemStore()
	_ = st.PutChannelConnection(context.Background(), &store.ChannelConnection{
		UserID: "usr_op", Kind: "telegram", Address: "555",
	})

	n := NewNotifier(NewWithBase(ts.URL, ts.Client()), st, "https://console.example")
	n.ConsentParked(&store.ConsentRequest{
		ID: "creq_1", TargetID: "gh", Principal: "usr_op", AgentName: "claude-code",
		Scopes: []string{"files:write"}, Reason: "tool: write_file",
	})

	sent := waitSent(t, fake, 1)
	if len(sent) != 1 {
		t.Fatalf("sendMessage calls = %d, want 1", len(sent))
	}
	if sent[0]["chat_id"] != "555" {
		t.Fatalf("chat_id = %v", sent[0]["chat_id"])
	}
	text, _ := sent[0]["text"].(string)
	for _, want := range []string{"claude-code", "files:write", "gh", "write_file"} {
		if !strings.Contains(text, want) {
			t.Fatalf("notice text missing %q: %q", want, text)
		}
	}
	// the notice must carry the approve/deny buttons bound to this request
	raw, _ := json.Marshal(sent[0]["reply_markup"])
	for _, want := range []string{"d:grant:creq_1", "d:deny:creq_1"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("notice missing decision button %q: %s", want, raw)
		}
	}
}

// The /start handshake: a valid token binds the chat to the token's user; junk gets a polite
// failure and binds nothing.
func TestLinkHandlerBindsChat(t *testing.T) {
	st := store.NewMemStore()
	ctx := context.Background()
	_ = st.PutChannelLinkToken(ctx, &store.ChannelLinkToken{
		Token: "tok_ok", UserID: "usr_op", Kind: "telegram", ExpiresAt: 9_000_000_000_000,
	})

	h := NewLinkHandler(st, func() int64 { return 1000 })
	reply := h(ctx, "tok_ok", "555", "ilya")
	if !strings.Contains(reply, "onnected") {
		t.Fatalf("success reply: %q", reply)
	}
	conn, err := st.GetChannelConnection(ctx, "usr_op", "telegram")
	if err != nil || conn.Address != "555" || conn.Label != "@ilya" {
		t.Fatalf("connection: %+v err=%v", conn, err)
	}

	// bad token: no binding, apologetic reply
	reply = h(ctx, "tok_bogus", "777", "eve")
	if reply == "" || strings.Contains(reply, "onnected ✅") {
		t.Fatalf("bogus token reply: %q", reply)
	}
	if _, err := st.GetChannelConnection(ctx, "usr_op", "telegram"); err != nil {
		t.Fatalf("original connection should be untouched: %v", err)
	}
	if l, _ := st.ListChannelConnections(ctx, "usr_eve"); len(l) != 0 {
		t.Fatalf("bogus token must bind nothing: %+v", l)
	}
}

// Parity: when the row carries the dialogs' legible headline, the telegram notice uses it
// VERBATIM — risk markers, Why line and all — instead of reassembling a weaker summary.
func TestNotifierUsesStoredHeadlineVerbatim(t *testing.T) {
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()
	st := store.NewMemStore()
	_ = st.PutChannelConnection(context.Background(), &store.ChannelConnection{
		UserID: "usr_op", Kind: "telegram", Address: "555",
	})

	n := NewNotifier(NewWithBase(ts.URL, ts.Client()), st, "https://console.example")
	n.ConsentParked(&store.ConsentRequest{
		ID: "creq_1", TargetID: "gh", Principal: "usr_op", AgentName: "claude-code",
		Scopes: []string{"files:write"}, Reason: "tool: write_file",
		Headline: "claude-code wants to write a file on gh — modifies data · ⚠️ irreversible.\nWhy: \"save the meeting notes\"",
	})

	sent := waitSent(t, fake, 1)
	if len(sent) != 1 {
		t.Fatalf("sendMessage calls = %d", len(sent))
	}
	text, _ := sent[0]["text"].(string)
	for _, want := range []string{"⚠️ irreversible", `Why: "save the meeting notes"`, "files:write"} {
		if !strings.Contains(text, want) {
			t.Fatalf("notice missing %q: %q", want, text)
		}
	}
}

func TestNotifierSilentWithoutConnection(t *testing.T) {
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	n := NewNotifier(NewWithBase(ts.URL, ts.Client()), store.NewMemStore(), "https://console.example")
	n.ConsentParked(&store.ConsentRequest{ID: "creq_2", Principal: "usr_unlinked", Scopes: []string{"x"}})

	time.Sleep(150 * time.Millisecond)
	if got := fake.sentBodies(); len(got) != 0 {
		t.Fatalf("expected no sends for an unlinked user, got %+v", got)
	}
}
