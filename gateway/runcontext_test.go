package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/store"
)

// Every session of one run shares one conversation with a target; another run, or another
// target, gets another. The id gives away neither the session nor the target.
func TestRunContextIDIsPerRunAndTarget(t *testing.T) {
	st := store.NewMemStore()
	ctx := context.Background()
	for _, s := range []*store.Session{
		{Handle: "sess_root", Principal: "usr_op"},
		{Handle: "sess_pm", Principal: "usr_op", ParentHandle: "sess_root"},
		{Handle: "sess_qa", Principal: "usr_op", ParentHandle: "sess_pm"},
		{Handle: "sess_other", Principal: "usr_op"},
	} {
		st.PutSession(ctx, s)
	}
	eng := &Gateway{st: st, targetID: "engineer"}
	root, pm, qa := eng.runContextID(ctx, "sess_root"), eng.runContextID(ctx, "sess_pm"), eng.runContextID(ctx, "sess_qa")
	if root == "" || root != pm || pm != qa {
		t.Errorf("one run, several ids: %q %q %q", root, pm, qa)
	}
	if other := eng.runContextID(ctx, "sess_other"); other == root {
		t.Error("two runs share a conversation")
	}
	if designer := (&Gateway{st: st, targetID: "designer"}).runContextID(ctx, "sess_pm"); designer == root {
		t.Error("two agents share a conversation id")
	}
	if strings.Contains(root, "sess_") || strings.Contains(root, "engineer") {
		t.Errorf("the id leaks what it is made of: %s", root)
	}
	if eng.runContextID(ctx, "") != "" || (&Gateway{targetID: "x"}).runContextID(ctx, "sess_root") != "" {
		t.Error("an id outside a run")
	}
}

// The run's conversation is what the agent is sent, whatever context_id the caller passed.
func TestAgentCallsCarryTheRunsContext(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Engineer", URL: srv.URL + "/a2a", Skills: []a2a.Skill{{ID: "build", Name: "Build", Description: "Builds."}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64 `json:"id"`
			Params struct {
				Message struct {
					ContextID string `json:"contextId"`
				} `json:"message"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		seen = append(seen, req.Params.Message.ContextID)
		mu.Unlock()
		task := a2a.Task{Kind: "task", ID: "t1", ContextID: req.Params.Message.ContextID, Status: a2a.TaskStatus{State: a2a.StateCompleted}}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": task})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()
	up, err := newA2AUpstream(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	up.Call(context.Background(), UpstreamCall{Name: "build", Args: map[string]any{"message": "a", "context_id": "someone-elses"}, Session: "s", ContextID: "run-abc"})
	up.Call(context.Background(), UpstreamCall{Name: "build", Args: map[string]any{"message": "b", "context_id": "mine"}, Session: "s"})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "run-abc" || seen[1] != "mine" {
		t.Errorf("contexts sent = %v", seen)
	}
}
