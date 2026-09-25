// Package dclient is how a demo agent consumes OTHER targets through Delegent: an MCP client
// on Delegent's /mcp endpoint, authenticated with the agent's own key, echoing the Delegent
// session the agent was called under on every request. That echo is the whole integration
// contract — see the plan: "the agent's one job is to send the header back".
//
// Consent is the operator's, not the agent's: a call that needs approval comes back as
// "PENDING human approval"; the client retries it for a while so the human has time to decide
// in the dashboard or with `delegent approvals`.
package dclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/a2a"
)

// Client is one agent's view of Delegent.
type Client struct {
	Endpoint string // http://host:8090/mcp
	KeyFile  string // file holding the dgk_… key (read per call, so it can appear after start)
	Key      string // or the key itself
	// ApprovalWait bounds how long a call keeps retrying while its consent is pending.
	ApprovalWait time.Duration
	Logf         func(format string, args ...any)
}

func (c *Client) key() (string, error) {
	if c.Key != "" {
		return c.Key, nil
	}
	if c.KeyFile == "" {
		return "", errors.New("no delegent key configured")
	}
	b, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return "", fmt.Errorf("delegent key not available yet (%s): %w", c.KeyFile, err)
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", errors.New("delegent key file is empty")
	}
	return k, nil
}

type headerTransport struct {
	key, session string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+h.key)
	if h.session != "" {
		r.Header.Set(a2a.SessionHeader, h.session) // the echo
	}
	return http.DefaultTransport.RoundTrip(r)
}

// Session is a connection to Delegent for ONE inbound task: everything it calls carries that
// task's session id, so Delegent keys the agent's grants per task.
type Session struct {
	c    *Client
	sess *mcp.ClientSession
}

// Open connects for the given inbound session (empty = a parentless, root call).
func (c *Client) Open(ctx context.Context, session string) (*Session, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Transport: headerTransport{key: key, session: session}}
	client := mcp.NewClient(&mcp.Implementation{Name: "delegent-demo-agent", Version: "0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: c.Endpoint, HTTPClient: hc, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to delegent at %s: %w", c.Endpoint, err)
	}
	return &Session{c: c, sess: sess}, nil
}

// Close ends the connection.
func (s *Session) Close() { _ = s.sess.Close() }

// Tools lists the vendor tools Delegent exposes to this agent (the "<target>__<tool>" ones).
func (s *Session) Tools(ctx context.Context) ([]*mcp.Tool, error) {
	res, err := s.sess.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	var out []*mcp.Tool
	for _, t := range res.Tools {
		if strings.Contains(t.Name, "__") {
			out = append(out, t)
		}
	}
	return out, nil
}

// Describe returns a tool's description as the gateway publishes it — the agent's own
// advertisement of what it covers — or "" when the tool is not offered.
func (s *Session) Describe(ctx context.Context, name string) string {
	tools, err := s.Tools(ctx)
	if err != nil {
		return ""
	}
	for _, t := range tools {
		if t.Name == name {
			return t.Description
		}
	}
	return ""
}

// Find returns the full "<target>__<tool>" name of the first tool whose vendor-side name is
// tool ("search_web"), whatever the operator named the target ("web", "web-search", …).
// Empty when the gateway offers no such tool to this agent.
func (s *Session) Find(ctx context.Context, tool string) string {
	tools, err := s.Tools(ctx)
	if err != nil {
		return ""
	}
	for _, t := range tools {
		if strings.HasSuffix(t.Name, "__"+tool) {
			return t.Name
		}
	}
	return ""
}

// Call invokes one tool, retrying while its consent is pending. status, when set, gets a line
// each time the call is parked on a human.
func (s *Session) Call(ctx context.Context, name string, args map[string]any, intent string, status func(string)) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	if intent != "" {
		args["_delegent_intent"] = intent
	}
	wait := s.c.ApprovalWait
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	deadline := time.Now().Add(wait)
	for attempt := 1; ; attempt++ {
		res, err := s.sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		text := flatten(res)
		if res.IsError {
			return "", fmt.Errorf("%s refused: %s", name, text)
		}
		if strings.Contains(text, "PENDING human approval") {
			if status != nil {
				status("waiting for the operator to approve " + name + " (attempt " + fmt.Sprint(attempt) + ")")
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf("%s: no human approved it within %s", name, wait)
			}
			s.c.logf("%s pending approval — retrying in 5s", name)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		// A same-turn console grant returns "granted … Retry 'x' now." without running the tool.
		if strings.Contains(text, "granted access at the console") && strings.Contains(text, "Retry") {
			s.c.logf("%s granted — retrying the call", name)
			continue
		}
		// A long-running agent task is handed back with its id before the gateway's wait
		// budget runs out. Poll it here, so the brain only ever sees a finished answer.
		if taskID := stillWorking(text); taskID != "" {
			return s.awaitTask(ctx, name, taskID, status)
		}
		return text, nil
	}
}

var (
	stillWorkingRe = regexp.MustCompile(`agent task (\S+) is still working`)
	taskIDRe       = regexp.MustCompile(`get_task \{task_id: "([^"]+)"\}`)
)

// stillWorking extracts the task id from a "still working — check later with get_task" result.
func stillWorking(text string) string {
	if m := taskIDRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	if m := stillWorkingRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

// awaitTask polls <target>__get_task until the task settles, reporting progress as status.
func (s *Session) awaitTask(ctx context.Context, tool, taskID string, status func(string)) (string, error) {
	target, _, _ := strings.Cut(tool, "__")
	getTask := target + "__get_task"
	wait := s.c.ApprovalWait
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	deadline := time.Now().Add(wait * 2)
	for {
		if status != nil {
			status("waiting for " + target + " to finish task " + taskID)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(3 * time.Second):
		}
		res, err := s.sess.CallTool(ctx, &mcp.CallToolParams{Name: getTask, Arguments: map[string]any{"task_id": taskID}})
		if err != nil {
			return "", fmt.Errorf("%s: %w", getTask, err)
		}
		text := flatten(res)
		if res.IsError {
			return "", fmt.Errorf("%s failed: %s", tool, text)
		}
		if stillWorking(text) == "" {
			return text, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s: task %s did not finish within %s", tool, taskID, wait*2)
		}
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func flatten(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, ct := range res.Content {
		if tc, ok := ct.(*mcp.TextContent); ok {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(tc.Text)
		}
	}
	if b.Len() == 0 && res.StructuredContent != nil {
		j, _ := json.Marshal(res.StructuredContent)
		b.Write(j)
	}
	return b.String()
}
