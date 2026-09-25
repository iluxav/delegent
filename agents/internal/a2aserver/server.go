// Package a2aserver is a small A2A agent host for the demo agents: it publishes an Agent
// Card, requires the agent's inbound secret on the JSON-RPC endpoint, and runs each
// message/send as an asynchronous task the caller polls with tasks/get. Handlers receive the
// Delegent session the call arrived under (the X-Delegent-Session header, or the message's
// metadata) so they can echo it on their own outbound calls — the one thing an agent behind
// Delegent has to do to keep the chain intact.
package a2aserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"delegent.dev/gateway/a2a"
)

// Call is one inbound request as a handler sees it.
type Call struct {
	Skill     string // metadata.skill, or the card's first skill
	Text      string // the message text
	Session   string // the caller's Delegent session (may be empty)
	ContextID string
	TaskID    string
	// History is the conversation so far in this context (earlier user messages and the
	// agent's replies, oldest first), so a follow-up like "now email it to bob" has something
	// to refer to. Empty on the first message of a context.
	History []a2a.Message
	// Status updates the task's status message while the handler works; Delegent forwards
	// each change as progress to the caller.
	Status func(string)
}

// Handler does the agent's work for one call and returns what to say.
type Handler func(ctx context.Context, c Call) (string, error)

// Server hosts one agent.
type Server struct {
	Card    a2a.Card
	Secret  string // required inbound Bearer; "" disables the check
	Handler Handler
	Logf    func(format string, args ...any)

	mu       sync.Mutex
	tasks    map[string]*a2a.Task
	contexts map[string][]a2a.Message // contextId → the conversation so far
	n        int
}

// maxContextTurns bounds how much history a context carries forward.
const maxContextTurns = 12

// Routes mounts the card and the JSON-RPC endpoint (at the card's URL path).
func (s *Server) Routes(mux *http.ServeMux) {
	if s.tasks == nil {
		s.tasks = map[string]*a2a.Task{}
	}
	if s.contexts == nil {
		s.contexts = map[string][]a2a.Message{}
	}
	if s.Logf == nil {
		s.Logf = log.Printf
	}
	mux.HandleFunc("GET "+a2a.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Card)
	})
	path := "/"
	if i := strings.Index(strings.TrimPrefix(s.Card.URL, "http://"), "/"); i >= 0 {
		path = strings.TrimPrefix(s.Card.URL, "http://")[i:]
	}
	mux.HandleFunc("POST "+path, s.rpc)
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *Server) rpc(w http.ResponseWriter, r *http.Request) {
	if s.Secret != "" {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Secret)) != 1 {
			s.Logf("rejected a call without my secret (from %s)", r.RemoteAddr)
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}
	var req rpcReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.reply(w, nil, nil, -32700, "parse error")
		return
	}
	switch req.Method {
	case "message/send", "message/stream":
		var p struct {
			Message a2a.Message `json:"message"`
			Config  struct {
				Blocking bool `json:"blocking"`
			} `json:"configuration"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			s.reply(w, req.ID, nil, -32602, "invalid params")
			return
		}
		session := strings.TrimSpace(r.Header.Get(a2a.SessionHeader))
		if session == "" {
			session, _ = p.Message.Metadata[a2a.SessionMetaKey].(string)
		}
		// A message addressed to an existing task never starts new work: a finished task
		// answers with its result, a running one with its status. (The demo agents take no
		// follow-up input, so there is no input-required path to feed.)
		if p.Message.TaskID != "" {
			if t := s.get(p.Message.TaskID); t != nil {
				s.Logf("task %s: message addressed to it while %s — returning its state, not starting anew", t.ID, t.Status.State)
				s.reply(w, req.ID, t, 0, "")
				return
			}
		}
		t := s.start(p.Message, session)
		if p.Config.Blocking {
			s.await(t.ID, 10*time.Minute)
		}
		s.reply(w, req.ID, s.get(t.ID), 0, "")
	case "tasks/get":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Params, &p)
		t := s.get(p.ID)
		if t == nil {
			s.reply(w, req.ID, nil, -32001, "task not found")
			return
		}
		s.reply(w, req.ID, t, 0, "")
	case "tasks/cancel":
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Params, &p)
		s.mu.Lock()
		if t, ok := s.tasks[p.ID]; ok && !a2a.Terminal(t.Status.State) {
			t.Status = a2a.TaskStatus{State: a2a.StateCanceled, Timestamp: now()}
		}
		s.mu.Unlock()
		s.reply(w, req.ID, s.get(p.ID), 0, "")
	default:
		s.reply(w, req.ID, nil, -32601, "method not found: "+req.Method)
	}
}

func (s *Server) reply(w http.ResponseWriter, id json.RawMessage, result any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if code != 0 {
		out["error"] = map[string]any{"code": code, "message": msg}
	} else {
		out["result"] = result
	}
	_ = json.NewEncoder(w).Encode(out)
}

// start records the task and runs the handler in the background.
func (s *Server) start(msg a2a.Message, session string) *a2a.Task {
	s.mu.Lock()
	s.n++
	id := fmt.Sprintf("task-%s-%d", strings.ToLower(strings.ReplaceAll(s.Card.Name, " ", "-")), s.n)
	ctxID := msg.ContextID
	if ctxID == "" {
		ctxID = "ctx-" + id
	}
	history := append([]a2a.Message(nil), s.contexts[ctxID]...)
	t := &a2a.Task{Kind: "task", ID: id, ContextID: ctxID, Status: a2a.TaskStatus{State: a2a.StateWorking, Timestamp: now()}, History: append(append([]a2a.Message(nil), history...), msg)}
	s.tasks[id] = t
	s.contexts[ctxID] = trimTurns(append(history, msg))
	s.mu.Unlock()

	skill, _ := msg.Metadata[a2a.SkillMetaKey].(string)
	if skill == "" && len(s.Card.Skills) > 0 {
		skill = s.Card.Skills[0].ID
	}
	call := Call{Skill: skill, Text: a2a.PartsText(msg.Parts), Session: session, ContextID: ctxID, TaskID: id, History: history, Status: func(line string) { s.setStatus(id, line) }}
	s.Logf("task %s: skill=%s session=%q context=%s (%d earlier turns) text=%q", id, skill, session, ctxID, len(history), call.Text)
	go func() {
		out, err := s.Handler(context.Background(), call)
		s.mu.Lock()
		defer s.mu.Unlock()
		t := s.tasks[id]
		if t.Status.State == a2a.StateCanceled {
			return
		}
		if err != nil {
			s.Logf("task %s FAILED: %v", id, err)
			t.Status = a2a.TaskStatus{State: a2a.StateFailed, Timestamp: now(), Message: &a2a.Message{Kind: "message", Role: "agent", MessageID: id + "-err", Parts: []a2a.Part{a2a.TextPart(err.Error())}}}
			return
		}
		s.Logf("task %s completed", id)
		t.Status = a2a.TaskStatus{State: a2a.StateCompleted, Timestamp: now()}
		t.Artifacts = []a2a.Artifact{{ArtifactID: id + "-result", Parts: []a2a.Part{a2a.TextPart(out)}}}
		reply := a2a.Message{Kind: "message", Role: "agent", MessageID: id + "-reply", ContextID: t.ContextID, TaskID: id, Parts: []a2a.Part{a2a.TextPart(out)}}
		s.contexts[t.ContextID] = trimTurns(append(s.contexts[t.ContextID], reply))
	}()
	return t
}

func (s *Server) setStatus(id, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[id]; ok && t.Status.State == a2a.StateWorking {
		t.Status.Message = &a2a.Message{Kind: "message", Role: "agent", MessageID: id + "-status", Parts: []a2a.Part{a2a.TextPart(line)}}
		t.Status.Timestamp = now()
	}
}

func (s *Server) get(id string) *a2a.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil
	}
	cp := *t
	return &cp
}

func (s *Server) await(id string, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if t := s.get(id); t == nil || a2a.Terminal(t.Status.State) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func trimTurns(h []a2a.Message) []a2a.Message {
	if len(h) > maxContextTurns {
		return h[len(h)-maxContextTurns:]
	}
	return h
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
