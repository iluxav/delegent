package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBotAPI records Bot API calls and serves scripted getUpdates responses.
type fakeBotAPI struct {
	mu       sync.Mutex
	sent     []map[string]any // sendMessage bodies, in order
	edited   []map[string]any // editMessageText bodies, in order
	answered []map[string]any // answerCallbackQuery bodies, in order
	updates  []string         // getUpdates JSON responses, served one per call, then empty batches
	upCalls  int
	upOffset []string // the offset param seen on each getUpdates call
}

func (f *fakeBotAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.sent = append(f.sent, body)
			w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
		case strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.edited = append(f.edited, body)
			w.Write([]byte(`{"ok":true,"result":{}}`))
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.answered = append(f.answered, body)
			w.Write([]byte(`{"ok":true,"result":true}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.upOffset = append(f.upOffset, r.URL.Query().Get("offset"))
			i := f.upCalls
			f.upCalls++
			if i < len(f.updates) {
				w.Write([]byte(f.updates[i]))
				return
			}
			w.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	})
}

func (f *fakeBotAPI) sentBodies() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.sent...)
}

func TestSendConsentNotice(t *testing.T) {
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	c := NewWithBase(ts.URL, ts.Client())
	err := c.SendConsentNotice(context.Background(), "12345", Notice{
		RequestID:  "creq_9",
		Headline:   "Agent wants files:write on GitHub — 1 irreversible tool",
		ConsoleURL: "https://console.example/consent",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := fake.sentBodies()
	if len(sent) != 1 {
		t.Fatalf("want 1 sendMessage, got %d", len(sent))
	}
	body := sent[0]
	if body["chat_id"] != "12345" {
		t.Fatalf("chat_id = %v", body["chat_id"])
	}
	text, _ := body["text"].(string)
	if !strings.Contains(text, "files:write") {
		t.Fatalf("text missing headline: %q", text)
	}
	// inline keyboard: console URL button + approve/deny callback buttons bound to the request
	raw, _ := json.Marshal(body["reply_markup"])
	for _, want := range []string{"https://console.example/consent", "d:grant:creq_9", "d:deny:creq_9"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("reply_markup missing %q: %s", want, raw)
		}
	}
}

func TestPollerBindsStartToken(t *testing.T) {
	fake := &fakeBotAPI{updates: []string{
		`{"ok":true,"result":[{"update_id":7,"message":{"chat":{"id":555},"from":{"username":"ilya"},"text":"/start tok_abc"}}]}`,
	}}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	var mu sync.Mutex
	var gotToken, gotChat, gotUser string
	c := NewWithBase(ts.URL, ts.Client())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Poll(ctx, Handlers{OnLink: func(_ context.Context, token, chatID, username string) string {
			mu.Lock()
			gotToken, gotChat, gotUser = token, chatID, username
			mu.Unlock()
			cancel() // one update is enough
			return "Connected ✅"
		}})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not stop after cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotToken != "tok_abc" || gotChat != "555" || gotUser != "ilya" {
		t.Fatalf("handler got token=%q chat=%q user=%q", gotToken, gotChat, gotUser)
	}
	// the handler's reply was sent back to the chat
	sent := fake.sentBodies()
	if len(sent) != 1 || sent[0]["chat_id"] != "555" {
		t.Fatalf("reply not sent: %+v", sent)
	}
	if text, _ := sent[0]["text"].(string); !strings.Contains(text, "Connected") {
		t.Fatalf("reply text: %+v", sent[0])
	}
}

// Telegram REJECTS the entire sendMessage when an inline URL button points at a
// localhost/private URL ("Wrong HTTP URL") — a dev console URL must degrade to a text line,
// never kill the notice (the Approve/Deny callback buttons don't care about the URL).
func TestSendConsentNoticeLocalhostConsoleDegradesToText(t *testing.T) {
	fake := &fakeBotAPI{}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	c := NewWithBase(ts.URL, ts.Client())
	err := c.SendConsentNotice(context.Background(), "12345", Notice{
		RequestID:  "creq_9",
		Headline:   "agent wants files:write",
		ConsoleURL: "http://localhost:3000/approvals",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := fake.sentBodies()
	if len(sent) != 1 {
		t.Fatalf("want 1 sendMessage, got %d", len(sent))
	}
	raw, _ := json.Marshal(sent[0]["reply_markup"])
	if strings.Contains(string(raw), `"url"`) {
		t.Fatalf("localhost URL must not become a button: %s", raw)
	}
	for _, want := range []string{"d:grant:creq_9", "d:deny:creq_9"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("decision buttons missing %q: %s", want, raw)
		}
	}
	text, _ := sent[0]["text"].(string)
	if !strings.Contains(text, "http://localhost:3000/approvals") {
		t.Fatalf("console url should fall back into the text: %q", text)
	}
}

// A button tap arrives as a callback_query: the poller dispatches it to OnDecision, answers
// the callback (stops the client spinner), and edits the original message to the outcome text
// (which also removes the now-stale buttons).
func TestPollerDispatchesCallback(t *testing.T) {
	fake := &fakeBotAPI{updates: []string{
		`{"ok":true,"result":[{"update_id":9,"callback_query":{"id":"cbq1","from":{"username":"ilya"},"data":"d:grant:creq_7","message":{"message_id":42,"chat":{"id":555}}}}]}`,
	}}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	var mu sync.Mutex
	var gotReq, gotDecision, gotChat, gotUser string
	c := NewWithBase(ts.URL, ts.Client())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Poll(ctx, Handlers{OnDecision: func(_ context.Context, requestID, decision, chatID, username string) string {
			mu.Lock()
			gotReq, gotDecision, gotChat, gotUser = requestID, decision, chatID, username
			mu.Unlock()
			cancel()
			return "✅ Approved — files:write granted"
		}})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not stop after cancel")
	}

	mu.Lock()
	if gotReq != "creq_7" || gotDecision != "grant" || gotChat != "555" || gotUser != "ilya" {
		t.Fatalf("handler got req=%q decision=%q chat=%q user=%q", gotReq, gotDecision, gotChat, gotUser)
	}
	mu.Unlock()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.answered) != 1 || fake.answered[0]["callback_query_id"] != "cbq1" {
		t.Fatalf("answerCallbackQuery: %+v", fake.answered)
	}
	if len(fake.edited) != 1 {
		t.Fatalf("editMessageText calls: %+v", fake.edited)
	}
	ed := fake.edited[0]
	if ed["chat_id"] != "555" || ed["message_id"] != float64(42) {
		t.Fatalf("edit target: %+v", ed)
	}
	if text, _ := ed["text"].(string); !strings.Contains(text, "Approved") {
		t.Fatalf("edit text: %q", text)
	}
}

func TestPollerAdvancesOffsetAndIgnoresNoise(t *testing.T) {
	fake := &fakeBotAPI{updates: []string{
		// a non-/start message is ignored (no handler call, no reply) but still advances offset
		`{"ok":true,"result":[{"update_id":41,"message":{"chat":{"id":9},"text":"hello"}}]}`,
		`{"ok":true,"result":[{"update_id":42,"message":{"chat":{"id":9},"text":"/start tok_x"}}]}`,
	}}
	ts := httptest.NewServer(fake.handler())
	defer ts.Close()

	c := NewWithBase(ts.URL, ts.Client())
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Poll(ctx, Handlers{OnLink: func(_ context.Context, token, chatID, username string) string {
			calls++
			cancel()
			return ""
		}})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poller did not stop")
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1 (noise ignored)", calls)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	// after consuming update 41, the next getUpdates must ask from offset 42
	if len(fake.upOffset) < 2 || fake.upOffset[1] != "42" {
		t.Fatalf("offsets seen: %v — want second call at 42", fake.upOffset)
	}
}
