// Package a2a is Delegent's Agent-to-Agent (A2A) client: enough of the protocol to front an
// agent the way the gateway fronts an MCP server. It fetches an Agent Card, turns each
// published skill into a drafted tool classification (the same review-and-sign flow tools
// get), and sends messages / polls tasks over the agent's JSON-RPC endpoint with the
// injected credential. The caller's Delegent session rides along on every request — the
// `X-Delegent-Session` header and `metadata.delegent_session` — so an agent that is itself a
// Delegent consumer can hand it back and keep the chain intact.
//
// Wire shapes follow the A2A specification (message/send, tasks/get, tasks/cancel, the
// Task/Message/Part objects and the task state machine). Streaming (message/stream) is not
// used: a long task is polled with tasks/get, which every A2A agent must support.
package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// SessionHeader carries the caller's Delegent session handle to the agent. An agent that is
// itself a Delegent consumer echoes it on every call it makes for that request.
const SessionHeader = "X-Delegent-Session"

// SessionMetaKey is the same handle inside message.metadata, for agents that read the A2A
// message rather than the transport.
const SessionMetaKey = "delegent_session"

// SkillMetaKey names the skill a proxied tool call targets, inside message.metadata. A2A
// messages carry no skill selector of their own; agents that route by skill read this.
const SkillMetaKey = "skill"

// WellKnownPath is where an agent publishes its card.
const WellKnownPath = "/.well-known/agent-card.json"

// Card is the subset of an A2A Agent Card Delegent reads.
type Card struct {
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	URL                string                    `json:"url"`
	Version            string                    `json:"version"`
	ProtocolVersion    string                    `json:"protocolVersion,omitempty"`
	PreferredTransport string                    `json:"preferredTransport,omitempty"`
	Capabilities       Capabilities              `json:"capabilities"`
	DefaultInputModes  []string                  `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string                  `json:"defaultOutputModes,omitempty"`
	Skills             []Skill                   `json:"skills"`
	SecuritySchemes    map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	Security           []map[string][]string     `json:"security,omitempty"`
}

// Capabilities are the optional protocol features an agent declares.
type Capabilities struct {
	Streaming              bool `json:"streaming"`
	PushNotifications      bool `json:"pushNotifications"`
	StateTransitionHistory bool `json:"stateTransitionHistory"`
}

// Skill is one capability the agent advertises.
type Skill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// SecurityScheme is the OpenAPI-style auth declaration on a card.
type SecurityScheme struct {
	Type   string `json:"type"`             // "http" | "apiKey" | "oauth2" | "openIdConnect"
	Scheme string `json:"scheme,omitempty"` // "bearer" for type http
	In     string `json:"in,omitempty"`     // "header" | "query" for apiKey
	Name   string `json:"name,omitempty"`   // header/query name for apiKey
}

// CredentialKind maps the card's security schemes onto Delegent's credential kinds:
// "static_bearer" (http bearer, or an apiKey in the Authorization header), "query_param"
// (an apiKey in the query string), "oauth2", or "" when the card declares no auth.
func (c *Card) CredentialKind() string {
	for _, s := range c.SecuritySchemes {
		switch s.Type {
		case "http":
			if strings.EqualFold(s.Scheme, "bearer") {
				return "static_bearer"
			}
		case "apiKey":
			if strings.EqualFold(s.In, "query") {
				return "query_param"
			}
			return "static_bearer"
		case "oauth2", "openIdConnect":
			return "oauth2"
		}
	}
	return ""
}

// Message is an A2A message (one turn, from user or agent).
type Message struct {
	Kind      string         `json:"kind"` // "message"
	Role      string         `json:"role"` // "user" | "agent"
	Parts     []Part         `json:"parts"`
	MessageID string         `json:"messageId"`
	ContextID string         `json:"contextId,omitempty"`
	TaskID    string         `json:"taskId,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Part is one piece of message/artifact content. Only text and data parts are interpreted;
// file parts are passed through as a description.
type Part struct {
	Kind string         `json:"kind"` // "text" | "data" | "file"
	Text string         `json:"text,omitempty"`
	Data map[string]any `json:"data,omitempty"`
	File map[string]any `json:"file,omitempty"`
}

// TextPart builds a text part.
func TextPart(s string) Part { return Part{Kind: "text", Text: s} }

// Task is the stateful unit of work an agent returns for anything that is not an immediate
// reply.
type Task struct {
	Kind      string         `json:"kind"` // "task"
	ID        string         `json:"id"`
	ContextID string         `json:"contextId"`
	Status    TaskStatus     `json:"status"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	History   []Message      `json:"history,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// TaskStatus is the task's current state plus an optional agent message explaining it.
type TaskStatus struct {
	State     string   `json:"state"`
	Message   *Message `json:"message,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
}

// Artifact is an output the task produced.
type Artifact struct {
	ArtifactID  string `json:"artifactId"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Parts       []Part `json:"parts"`
}

// Task states, per the A2A specification.
const (
	StateSubmitted     = "submitted"
	StateWorking       = "working"
	StateInputRequired = "input-required"
	StateCompleted     = "completed"
	StateCanceled      = "canceled"
	StateFailed        = "failed"
	StateRejected      = "rejected"
	StateAuthRequired  = "auth-required"
	StateUnknown       = "unknown"
)

// Terminal reports whether a task state is final (no further polling makes sense).
func Terminal(state string) bool {
	switch state {
	case StateCompleted, StateCanceled, StateFailed, StateRejected:
		return true
	}
	return false
}

// NeedsCaller reports whether the task is parked waiting on the caller (input or auth).
func NeedsCaller(state string) bool {
	return state == StateInputRequired || state == StateAuthRequired
}

// --- JSON-RPC envelope ---

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("a2a error %d: %s", e.Code, e.Message) }

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// --- card discovery ---

// FetchCard resolves an agent's card from an endpoint the operator typed: the URL itself when
// it already names a card, else `<endpoint>/.well-known/agent-card.json`, else the same path at
// the endpoint's origin. credential (optional) is sent as a Bearer on every attempt, since some
// agents gate the card too.
func FetchCard(ctx context.Context, endpoint, credential string) (*Card, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid agent endpoint %q", endpoint)
	}
	var candidates []string
	if strings.HasSuffix(u.Path, "agent-card.json") || strings.HasSuffix(u.Path, "agent.json") {
		candidates = append(candidates, u.String())
	} else {
		base := strings.TrimSuffix(u.String(), "/")
		candidates = append(candidates, base+WellKnownPath)
		origin := u.Scheme + "://" + u.Host
		if origin+WellKnownPath != base+WellKnownPath {
			candidates = append(candidates, origin+WellKnownPath)
		}
	}
	var lastErr error
	for _, c := range candidates {
		card, err := getCard(ctx, c, credential)
		if err == nil {
			if card.URL == "" {
				// A card with no URL: the agent lives where the card was found (minus the path).
				card.URL = u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "/")
			}
			return card, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func getCard(ctx context.Context, cardURL, credential string) (*Card, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cardURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", cardURL, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var card Card
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, fmt.Errorf("%s is not an agent card: %w", cardURL, err)
	}
	if card.Name == "" && len(card.Skills) == 0 {
		return nil, fmt.Errorf("%s is not an agent card (no name, no skills)", cardURL)
	}
	return &card, nil
}

// --- the client ---

// Client talks to one agent's JSON-RPC endpoint.
type Client struct {
	URL        string
	Credential string // injected as Bearer; the caller never sees it
	HTTP       *http.Client
	// PollInterval / PollTimeout bound how long Send waits on a non-terminal task before
	// handing the task back to the caller as-is. Zero values take the defaults (1s / 10m).
	PollInterval time.Duration
	PollTimeout  time.Duration
	nextID       atomic.Int64
}

// SendOpts shape one message/send.
type SendOpts struct {
	Skill     string         // recorded in metadata.skill
	ContextID string         // continue an existing conversation
	TaskID    string         // answer a task that is input-required
	Session   string         // the caller's Delegent session handle
	Metadata  map[string]any // extra metadata merged in
	// Progress, when set, receives one line per state change while a task is polled.
	Progress func(string)
	// NoWait returns the first task the agent hands back without polling it to completion.
	NoWait bool
}

// Result is the normalised outcome of a message: what the agent said (message text, task
// status message, and artifacts flattened to text), the task's state, and the ids a caller
// needs to continue (context) or resume (task).
type Result struct {
	Text      string
	State     string // "" for an immediate message reply
	TaskID    string
	ContextID string
	Task      *Task    // set when the agent returned a task
	Message   *Message // set when the agent returned a plain message
}

// Send delivers text to the agent and returns the normalised result. A task that is not yet
// terminal is polled (tasks/get) until it is terminal or parked on the caller
// (input-required / auth-required), or until PollTimeout elapses.
func (c *Client) Send(ctx context.Context, text string, o SendOpts) (*Result, error) {
	meta := map[string]any{}
	for k, v := range o.Metadata {
		meta[k] = v
	}
	if o.Skill != "" {
		meta[SkillMetaKey] = o.Skill
	}
	if o.Session != "" {
		meta[SessionMetaKey] = o.Session
	}
	msg := Message{
		Kind: "message", Role: "user", Parts: []Part{TextPart(text)},
		MessageID: newID(), ContextID: o.ContextID, TaskID: o.TaskID, Metadata: meta,
	}
	params := map[string]any{"message": msg}
	var raw json.RawMessage
	if err := c.call(ctx, "message/send", params, o.Session, &raw); err != nil {
		return nil, err
	}
	res, err := normalise(raw)
	if err != nil {
		return nil, err
	}
	if res.Task == nil || o.NoWait || Terminal(res.State) || NeedsCaller(res.State) {
		return res, nil
	}
	return c.wait(ctx, res, o.Session, o.Progress)
}

// GetTask fetches a task by id.
func (c *Client) GetTask(ctx context.Context, taskID, session string) (*Result, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "tasks/get", map[string]any{"id": taskID}, session, &raw); err != nil {
		return nil, err
	}
	return normalise(raw)
}

// CancelTask asks the agent to cancel a task.
func (c *Client) CancelTask(ctx context.Context, taskID, session string) (*Result, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "tasks/cancel", map[string]any{"id": taskID}, session, &raw); err != nil {
		return nil, err
	}
	return normalise(raw)
}

// Wait polls a task until it settles. Exposed for callers that got a task back with NoWait.
func (c *Client) Wait(ctx context.Context, taskID, session string, progress func(string)) (*Result, error) {
	res, err := c.GetTask(ctx, taskID, session)
	if err != nil {
		return nil, err
	}
	if Terminal(res.State) || NeedsCaller(res.State) {
		return res, nil
	}
	return c.wait(ctx, res, session, progress)
}

func (c *Client) wait(ctx context.Context, res *Result, session string, progress func(string)) (*Result, error) {
	interval := c.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	timeout := c.PollTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	lastState, lastNote := res.State, statusNote(res)
	if progress != nil {
		progress(describe(res))
	}
	for {
		if time.Now().After(deadline) {
			return res, nil // hand the still-running task back; the caller can resume it
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(interval):
		}
		next, err := c.GetTask(ctx, res.TaskID, session)
		if err != nil {
			return res, err
		}
		res = next
		if note := statusNote(res); progress != nil && (res.State != lastState || note != lastNote) {
			progress(describe(res))
			lastState, lastNote = res.State, note
		}
		if Terminal(res.State) || NeedsCaller(res.State) {
			return res, nil
		}
	}
}

func describe(r *Result) string {
	s := "agent task " + r.TaskID + ": " + r.State
	if n := statusNote(r); n != "" {
		s += " — " + n
	}
	return s
}

func statusNote(r *Result) string {
	if r.Task == nil || r.Task.Status.Message == nil {
		return ""
	}
	return PartsText(r.Task.Status.Message.Parts)
}

// call posts one JSON-RPC request and decodes its result.
func (c *Client) call(ctx context.Context, method string, params any, session string, out *json.RawMessage) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: c.nextID.Add(1), Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	if session != "" {
		req.Header.Set(SessionHeader, session)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s: agent returned %s: %s", method, res.Status, truncate(string(raw), 300))
	}
	var env rpcResponse
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s: agent returned non-JSON-RPC body: %w", method, err)
	}
	if env.Error != nil {
		return env.Error
	}
	*out = env.Result
	return nil
}

// normalise decodes a message/send or tasks/get result (a Task or a Message) into a Result.
func normalise(raw json.RawMessage) (*Result, error) {
	var probe struct {
		Kind string `json:"kind"`
		// tasks have a status; messages have a role — used when kind is missing
		Status *json.RawMessage `json:"status"`
		Role   string           `json:"role"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("undecodable agent result: %w", err)
	}
	kind := probe.Kind
	if kind == "" {
		if probe.Status != nil {
			kind = "task"
		} else if probe.Role != "" {
			kind = "message"
		}
	}
	switch kind {
	case "task":
		var t Task
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, err
		}
		if t.Status.State == "" {
			t.Status.State = StateUnknown
		}
		return &Result{Text: TaskText(&t), State: t.Status.State, TaskID: t.ID, ContextID: t.ContextID, Task: &t}, nil
	case "message":
		var m Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		return &Result{Text: PartsText(m.Parts), ContextID: m.ContextID, TaskID: m.TaskID, Message: &m}, nil
	}
	return nil, errors.New("agent result is neither a task nor a message")
}

// TaskText flattens what a task has to say: its artifacts (text/data parts), and — when there
// are none — its status message.
func TaskText(t *Task) string {
	var b strings.Builder
	for _, a := range t.Artifacts {
		s := PartsText(a.Parts)
		if s == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		if a.Name != "" {
			b.WriteString(a.Name + ": ")
		}
		b.WriteString(s)
	}
	if b.Len() == 0 && t.Status.Message != nil {
		b.WriteString(PartsText(t.Status.Message.Parts))
	}
	return b.String()
}

// PartsText joins the text of a part list; data parts render as compact JSON, file parts as
// a placeholder naming the file.
func PartsText(parts []Part) string {
	var out []string
	for _, p := range parts {
		switch p.Kind {
		case "text":
			if p.Text != "" {
				out = append(out, p.Text)
			}
		case "data":
			if len(p.Data) > 0 {
				b, _ := json.Marshal(p.Data)
				out = append(out, string(b))
			}
		case "file":
			name, _ := p.File["name"].(string)
			if name == "" {
				name = "unnamed"
			}
			out = append(out, "[file: "+name+"]")
		default:
			if p.Text != "" {
				out = append(out, p.Text)
			}
		}
	}
	return strings.Join(out, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var idCounter atomic.Int64

// newID makes a message id unique within this process; A2A only needs uniqueness per
// conversation.
func newID() string {
	return fmt.Sprintf("msg-%d-%d", time.Now().UnixNano(), idCounter.Add(1))
}
