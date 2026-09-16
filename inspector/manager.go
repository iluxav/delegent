package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	transcriptLimit = 500
	connectTimeout  = 30 * time.Second
)

// Elicitation is a server → client elicitation/create request waiting for a person to
// answer it in the browser. The SDK handler blocks on answer until the UI resolves it.
type Elicitation struct {
	ID      string
	At      time.Time
	Message string
	Mode    string // "" or "form" · "url"
	URL     string
	Schema  any
	Fields  []Field
	answer  chan *mcp.ElicitResult
}

// Server is one configured MCP server: its spec, the live session when connected, the
// transcript of everything that crossed the wire, and any elicitations awaiting an answer.
type Server struct {
	Spec       *ServerSpec
	Transcript *Transcript

	mu         sync.Mutex
	session    *mcp.ClientSession
	connecting bool
	err        string
	pending    map[string]*Elicitation
}

func newServer(spec *ServerSpec) *Server {
	return &Server{Spec: spec, Transcript: NewTranscript(transcriptLimit), pending: map[string]*Elicitation{}}
}

func (s *Server) Name() string { return s.Spec.Name }

// Session is the live session, or nil.
func (s *Server) Session() *mcp.ClientSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

func (s *Server) Connected() bool { return s.Session() != nil }

func (s *Server) Connecting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connecting
}

// Err is the last connect failure or disconnect reason; cleared by a successful connect.
func (s *Server) Err() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Info is the server's initialize result (identity, capabilities, instructions), or nil.
func (s *Server) Info() *mcp.InitializeResult {
	if ss := s.Session(); ss != nil {
		return ss.InitializeResult()
	}
	return nil
}

// Connect opens the session. It is a no-op when already connected or connecting. The
// session outlives the HTTP request that started it, so it is not bound to that context.
func (s *Server) Connect() error {
	s.mu.Lock()
	if s.session != nil || s.connecting {
		s.mu.Unlock()
		return nil
	}
	s.connecting = true
	s.mu.Unlock()

	sess, err := s.dial()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.connecting = false
	if err != nil {
		s.err = err.Error()
		s.Transcript.Event("connect failed: " + err.Error())
		return err
	}
	s.session = sess
	s.err = ""
	info := sess.InitializeResult()
	s.Transcript.Event(fmt.Sprintf("connected to %s %s (protocol %s)", info.ServerInfo.Name, info.ServerInfo.Version, info.ProtocolVersion))
	// The transport is the connection: when it ends for any reason, reflect that.
	go func() {
		werr := sess.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.session != sess {
			return // already replaced or closed on purpose
		}
		s.session = nil
		s.err = "connection closed"
		if werr != nil {
			s.err = "connection closed: " + werr.Error()
		}
		s.Transcript.Event(s.err)
	}()
	return nil
}

func (s *Server) dial() (*mcp.ClientSession, error) {
	transport, err := s.transport()
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-inspector", Version: version}, &mcp.ClientOptions{
		ElicitationHandler: s.handleElicitation,
	})
	client.AddSendingMiddleware(s.Transcript.Middleware("send"))
	client.AddReceivingMiddleware(s.Transcript.Middleware("recv"))

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	return client.Connect(ctx, transport, nil)
}

func (s *Server) transport() (mcp.Transport, error) {
	spec := s.Spec
	switch spec.Kind() {
	case KindStdio:
		cmd := exec.Command(spec.Command, spec.Args...)
		cmd.Env = os.Environ()
		for k, v := range spec.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		cmd.Dir = spec.Cwd
		// A stdio server's stderr is its only log; capture it line by line.
		cmd.Stderr = &lineWriter{emit: func(line string) { s.Transcript.Add(Entry{Dir: "stderr", Text: line}) }}
		return &mcp.CommandTransport{Command: cmd}, nil
	case KindHTTP:
		// Default off: the standalone SSE stream is a long-lived GET some servers answer slowly,
		// stalling connect. Opt in per server with "standaloneSSE": true to watch server-pushed
		// notifications.
		return &mcp.StreamableClientTransport{Endpoint: spec.URL, HTTPClient: httpClient(spec.Headers), DisableStandaloneSSE: !spec.StandaloneSSE}, nil
	case KindSSE:
		return &mcp.SSEClientTransport{Endpoint: spec.URL, HTTPClient: httpClient(spec.Headers)}, nil
	}
	return nil, fmt.Errorf("unknown transport %q", spec.Kind())
}

// Disconnect closes the session; the Wait goroutine sees s.session != sess and stays quiet.
func (s *Server) Disconnect() {
	s.mu.Lock()
	sess := s.session
	s.session = nil
	s.err = ""
	for id, e := range s.pending {
		close(e.answer)
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
		s.Transcript.Event("disconnected")
	}
}

func (s *Server) handleElicitation(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	p := req.Params
	e := &Elicitation{
		ID: newID(), At: time.Now(), Message: p.Message, Mode: p.Mode, URL: p.URL, Schema: p.RequestedSchema,
		answer: make(chan *mcp.ElicitResult, 1),
	}
	e.Fields, _ = SchemaFields(p.RequestedSchema)
	s.mu.Lock()
	s.pending[e.ID] = e
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, e.ID)
		s.mu.Unlock()
	}()
	select {
	case r, ok := <-e.answer:
		if !ok {
			return nil, errors.New("inspector disconnected")
		}
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Pending lists elicitations awaiting an answer, oldest first.
func (s *Server) Pending() []*Elicitation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Elicitation, 0, len(s.pending))
	for _, e := range s.pending {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Answer resolves a pending elicitation; false when it is gone (answered, cancelled, or the
// server stopped waiting).
func (s *Server) Answer(id string, res *mcp.ElicitResult) bool {
	s.mu.Lock()
	e, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	e.answer <- res
	return true
}

// Manager holds every configured server, keyed by name, and the config they came from.
type Manager struct {
	configPath string

	mu         sync.RWMutex
	servers    map[string]*Server
	configText string
}

func NewManager(configPath string) *Manager {
	return &Manager{configPath: configPath, servers: map[string]*Server{}}
}

// LoadFile applies the saved config, if any.
func (m *Manager) LoadFile() error {
	specs, err := LoadConfigFile(m.configPath)
	if err != nil {
		return err
	}
	m.apply(specs)
	return nil
}

// Load parses a pasted mcpServers config, applies it, and saves it. Servers that keep their
// name keep their live session (the new spec applies on the next connect); servers that
// disappear are disconnected and dropped.
func (m *Manager) Load(text string) error {
	specs, err := ParseConfig([]byte(text))
	if err != nil {
		return err
	}
	m.apply(specs)
	if m.configPath == "" {
		return nil
	}
	return SaveConfigFile(m.configPath, specs)
}

func (m *Manager) apply(specs []*ServerSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, spec := range specs {
		keep[spec.Name] = true
		if s, ok := m.servers[spec.Name]; ok {
			s.Spec = spec
			continue
		}
		m.servers[spec.Name] = newServer(spec)
	}
	for name, s := range m.servers {
		if !keep[name] {
			s.Disconnect()
			delete(m.servers, name)
		}
	}
	m.configText = string(MarshalConfig(specs))
}

// ConfigText is the normalized config, for the paste box.
func (m *Manager) ConfigText() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configText
}

func (m *Manager) Servers() []*Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Server, 0, len(m.servers))
	for _, s := range m.servers {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

func (m *Manager) Get(name string) (*Server, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.servers[name]
	return s, ok
}

// Close disconnects everything (shutdown).
func (m *Manager) Close() {
	for _, s := range m.Servers() {
		s.Disconnect()
	}
}

// --- helpers ---

type headerTransport struct {
	headers map[string]string
	base    http.RoundTripper
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return h.base.RoundTrip(r)
}

func httpClient(headers map[string]string) *http.Client {
	if len(headers) == 0 {
		return &http.Client{}
	}
	return &http.Client{Transport: headerTransport{headers: headers, base: http.DefaultTransport}}
}

// lineWriter splits a stream into lines and hands each complete one to emit.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	emit func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.emit(string(bytes.TrimRight(w.buf[:i], "\r")))
		w.buf = w.buf[i+1:]
	}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
