package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

// slowA2A is an agent whose tasks keep working until they are cancelled; it records the ids
// it was asked to cancel.
type slowA2A struct {
	mu        sync.Mutex
	canceled  []string
	cancelled map[string]bool
}

func (f *slowA2A) start(t *testing.T) *httptest.Server {
	t.Helper()
	f.cancelled = map[string]bool{}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(a2a.Card{Name: "Engineer", URL: srv.URL + "/a2a", Skills: []a2a.Skill{{ID: "build_feature", Name: "Build", Description: "Builds."}}})
	})
	mux.HandleFunc("POST /a2a", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64  `json:"id"`
			Method string `json:"method"`
			Params struct {
				ID string `json:"id"`
			} `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		id := "task-1"
		if req.Params.ID != "" {
			id = req.Params.ID
		}
		f.mu.Lock()
		if req.Method == "tasks/cancel" {
			f.canceled = append(f.canceled, id)
			f.cancelled[id] = true
		}
		state := a2a.StateWorking
		if f.cancelled[id] {
			state = a2a.StateCanceled
		}
		f.mu.Unlock()
		task := a2a.Task{Kind: "task", ID: id, ContextID: "ctx", Status: a2a.TaskStatus{State: state}}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": task})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A task an agent started for a run is remembered from its first moment, and stopping the
// run cancels it on the agent, which ends the call that was waiting on it. Tasks of other
// sessions are left alone.
func TestCancelSessionsStopsTheRunsAgentTasks(t *testing.T) {
	agent := &slowA2A{}
	srv := agent.start(t)
	up, err := newA2AUpstream(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	up.client.PollInterval = 10 * time.Millisecond

	done := make(chan string, 1)
	go func() {
		done <- mustText(up.Call(context.Background(), UpstreamCall{Name: "build_feature", Args: map[string]any{"message": "build it"}, Session: "sess_engineer"}))
	}()
	deadline := time.Now().Add(2 * time.Second)
	for up.running("sess_engineer|build_feature||build it") == "" {
		if time.Now().After(deadline) {
			t.Fatal("the task was not remembered while it ran")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if n := up.cancelSessions(context.Background(), map[string]bool{"sess_other": true}); n != 0 {
		t.Fatalf("cancelled %d tasks of another run", n)
	}
	if n := up.cancelSessions(context.Background(), map[string]bool{"sess_root": true, "sess_engineer": true}); n != 1 {
		t.Fatalf("cancelled %d tasks, want 1", n)
	}
	select {
	case txt := <-done:
		if !strings.Contains(txt, "canceled") {
			t.Errorf("the waiting call should end with the cancellation: %q", txt)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiting call did not end after the task was cancelled")
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if len(agent.canceled) != 1 || agent.canceled[0] != "task-1" {
		t.Errorf("agent saw cancels %v", agent.canceled)
	}
}

// StopRun revokes the run's sessions and records the stop; another owner's run is not theirs
// to stop.
func TestStopRun(t *testing.T) {
	st := store.NewMemStore()
	ctx := context.Background()
	for _, s := range []*store.Session{
		{Handle: "root", Principal: "usr_op"},
		{Handle: "hop", Principal: "usr_op", ParentHandle: "root"},
	} {
		st.PutSession(ctx, s)
	}
	r := NewRegistry(st, keyring.Sealer(nil))
	if _, err := r.StopRun("usr_someone_else", "root"); err != ErrNoSuchRun {
		t.Fatalf("another owner stopped the run: %v", err)
	}
	if _, err := r.StopRun("usr_op", "nope"); err != ErrNoSuchRun {
		t.Fatalf("unknown run: %v", err)
	}
	// After a gateway restart the root session is gone; with the run's known tasks the stop
	// still goes ahead (and is recorded), revoking nothing.
	if rep, err := r.StopRun("usr_op", "sess_before_restart", RunTask{Target: "tgt", TaskID: "t1", Session: "sess_hop_before"}); err != nil || rep.Revoked != 0 {
		t.Fatalf("stop after restart: %+v %v", rep, err)
	}
	rep, err := r.StopRun("usr_op", "root")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Sessions != 2 || rep.Revoked != 2 {
		t.Errorf("report = %+v", rep)
	}
	for _, h := range []string{"root", "hop"} {
		if ss, _ := st.GetSession(ctx, h); ss.RevokedAt == 0 {
			t.Errorf("%s still live", h)
		}
	}
	evs, _ := st.ListEvents(ctx, store.EventFilter{UserID: "usr_op", Limit: store.EventLimitAll})
	if len(evs) != 2 || evs[0].Type != store.EventRunStopped || evs[1].Type != store.EventRunStopped {
		t.Errorf("events = %+v", evs)
	}
}
