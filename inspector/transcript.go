package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Entry is one line of a server's transcript: a request or notification in either
// direction, a line the child process wrote to stderr, or an inspector event.
type Entry struct {
	Seq      int
	At       time.Time
	Dir      string // "send" client→server · "recv" server→client · "stderr" · "event"
	Method   string
	Text     string // stderr line or event text
	Params   string // pretty JSON
	Result   string // pretty JSON
	Error    string
	Duration time.Duration
}

func (e Entry) Notification() bool { return strings.HasPrefix(e.Method, "notifications/") }
func (e Entry) Clock() string      { return e.At.Format("15:04:05.000") }

// Took renders the round-trip time; empty for notifications and non-RPC lines.
func (e Entry) Took() string {
	if e.Dir == "stderr" || e.Dir == "event" || e.Notification() {
		return ""
	}
	d := e.Duration
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.1f s", d.Seconds())
	default:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
}

// Transcript is a bounded, ordered log per server. Seq keeps increasing across Clear so a
// client that asks for "everything after N" never replays old lines.
type Transcript struct {
	mu      sync.Mutex
	entries []Entry
	seq     int
	limit   int
}

func NewTranscript(limit int) *Transcript { return &Transcript{limit: limit} }

func (t *Transcript) Add(e Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	e.Seq = t.seq
	if e.At.IsZero() {
		e.At = time.Now()
	}
	t.entries = append(t.entries, e)
	if len(t.entries) > t.limit {
		t.entries = t.entries[len(t.entries)-t.limit:]
	}
}

func (t *Transcript) Event(text string) { t.Add(Entry{Dir: "event", Text: text}) }

// Since returns entries with Seq > after, newest first.
func (t *Transcript) Since(after int) []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Entry
	for i := len(t.entries) - 1; i >= 0; i-- {
		if t.entries[i].Seq <= after {
			break
		}
		out = append(out, t.entries[i])
	}
	return out
}

func (t *Transcript) LastSeq() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seq
}

func (t *Transcript) Clear() {
	t.mu.Lock()
	t.entries = nil
	t.mu.Unlock()
}

// Middleware records every method that passes through the client in the given direction —
// requests and notifications alike, including the initialize handshake — with its params,
// result or error, and how long the round trip took.
func (t *Transcript) Middleware(dir string) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			start := time.Now()
			res, err := next(ctx, method, req)
			e := Entry{Dir: dir, Method: method, Params: pretty(req.GetParams()), Duration: time.Since(start)}
			if err != nil {
				e.Error = err.Error()
			} else if res != nil {
				e.Result = pretty(res)
			}
			t.Add(e)
			return res, err
		}
	}
}

// pretty renders v as indented JSON; nil and JSON null render as "".
func pretty(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	if string(b) == "null" {
		return ""
	}
	return string(b)
}
