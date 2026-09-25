package a2aserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"delegent.dev/gateway/a2a"
)

// A message that names an existing task returns that task; it never starts a second one.
func TestMessageToExistingTaskDoesNotRestart(t *testing.T) {
	var runs atomic.Int32
	release := make(chan struct{})
	s := &Server{Card: a2a.Card{Name: "T", URL: "http://x/a2a", Skills: []a2a.Skill{{ID: "do"}}}, Logf: func(string, ...any) {},
		Handler: func(ctx context.Context, c Call) (string, error) { runs.Add(1); <-release; return "done", nil }}
	mux := http.NewServeMux()
	s.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	send := func(taskID string) a2a.Task {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": map[string]any{"message": a2a.Message{Kind: "message", Role: "user", MessageID: "m", TaskID: taskID, Parts: []a2a.Part{a2a.TextPart("go")}}}})
		res, err := http.Post(srv.URL+"/a2a", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out struct {
			Result a2a.Task `json:"result"`
		}
		json.NewDecoder(res.Body).Decode(&out)
		return out.Result
	}
	first := send("")
	again := send(first.ID)
	if again.ID != first.ID || again.Status.State != a2a.StateWorking {
		t.Errorf("message to the running task returned %+v", again)
	}
	close(release)
	time.Sleep(50 * time.Millisecond)
	done := send(first.ID)
	if done.Status.State != a2a.StateCompleted || len(done.Artifacts) == 0 {
		t.Errorf("message to the finished task returned %+v", done)
	}
	if n := runs.Load(); n != 1 {
		t.Errorf("handler ran %d times, want 1", n)
	}
}

// A second message in the same context carries the earlier turns, including the agent's
// reply, so a follow-up has something to refer to.
func TestContextCarriesHistory(t *testing.T) {
	var seen [][]a2a.Message
	s := &Server{Card: a2a.Card{Name: "T", URL: "http://x/a2a", Skills: []a2a.Skill{{ID: "do"}}}, Logf: func(string, ...any) {},
		Handler: func(ctx context.Context, c Call) (string, error) {
			seen = append(seen, c.History)
			return "reply to " + c.Text, nil
		}}
	mux := http.NewServeMux()
	s.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	send := func(ctxID, text string) a2a.Task {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": map[string]any{"message": a2a.Message{Kind: "message", Role: "user", MessageID: "m", ContextID: ctxID, Parts: []a2a.Part{a2a.TextPart(text)}}}})
		res, err := http.Post(srv.URL+"/a2a", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out struct {
			Result a2a.Task `json:"result"`
		}
		json.NewDecoder(res.Body).Decode(&out)
		return out.Result
	}
	first := send("", "research x")
	time.Sleep(50 * time.Millisecond)
	send(first.ContextID, "now email it")
	time.Sleep(50 * time.Millisecond)
	if len(seen) != 2 || len(seen[0]) != 0 || len(seen[1]) != 2 {
		t.Fatalf("history per call = %d/%d, want 0 then 2", len(seen[0]), len(seen[1]))
	}
	if seen[1][1].Role != "agent" || a2a.PartsText(seen[1][1].Parts) != "reply to research x" {
		t.Errorf("follow-up history = %+v", seen[1])
	}
	if fresh := send("", "unrelated"); fresh.ContextID == first.ContextID {
		t.Error("a message without a context must start a new one")
	}
}
