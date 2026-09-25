package brains

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"delegent.dev/agents/internal/a2aserver"
	"delegent.dev/gateway/a2a"
)

// OllamaOpts configure the LLM brain.
type OllamaOpts struct {
	URL      string // http://127.0.0.1:11434
	Model    string // llama3.2:3b, qwen3.5:9b, …
	System   string // the role's system prompt
	MaxSteps int    // tool-call iterations before giving up (default 8)
	// Tools limits what the model sees: a Delegent tool is offered when its name starts with
	// one of these ("librarian__", "mailer__") or ends with one ("__search_web", so the web
	// target may be called anything). Empty = everything the gateway exposes, which on a real
	// gateway means every vendor's tools and their descriptions — far more context than a
	// local model can use well. Delegent still decides what the agent may actually call.
	Tools []string
	// NumCtx is the context window to request. 0 = the server's default, which is what you want
	// when other clients (Pi) share the model: Ollama reloads a model whenever a request asks
	// for a different context size than the one it is running with, and a 27B reload costs
	// tens of seconds every time two clients disagree. Set OLLAMA_CONTEXT_LENGTH on the server
	// instead, once, for everyone.
	NumCtx int
	// Think enables the model's thinking mode (Qwen3 and the like) — better at multi-step tool
	// use, several times slower per step. Off by default for the demo.
	Think bool
}

// Ollama makes an agent that reasons with a local model: it lists the tools Delegent exposes
// to it, lets the model call them (each call goes through Delegent under the inbound session,
// consent and all), and returns the model's final answer. Leaf agents (no Delegent) just chat.
func Ollama(d Deps, o OllamaOpts) a2aserver.Handler {
	if o.URL == "" {
		o.URL = "http://127.0.0.1:11434"
	}
	if o.MaxSteps <= 0 {
		o.MaxSteps = 8
	}

	allowed := func(name string) bool {
		if len(o.Tools) == 0 {
			return true
		}
		for _, p := range o.Tools {
			if strings.HasPrefix(name, p) || (strings.HasPrefix(p, "__") && strings.HasSuffix(name, p)) {
				return true
			}
		}
		return false
	}
	return func(ctx context.Context, c a2aserver.Call) (string, error) {
		msgs := []chatMsg{{Role: "system", Content: o.System}}
		for _, m := range c.History {
			role := "user"
			if m.Role == "agent" {
				role = "assistant"
			}
			msgs = append(msgs, chatMsg{Role: role, Content: a2a.PartsText(m.Parts)})
		}
		msgs = append(msgs, chatMsg{Role: "user", Content: c.Text})
		var tools []toolDef
		var call func(name string, args map[string]any) (string, error)
		if d.Delegent != nil {
			s, err := d.Delegent.Open(ctx, c.Session)
			if err != nil {
				return "", err
			}
			defer s.Close()
			list, err := s.Tools(ctx)
			if err != nil {
				return "", err
			}
			for _, t := range list {
				if !allowed(t.Name) {
					continue
				}
				params := t.InputSchema
				if params == nil {
					params = map[string]any{"type": "object", "properties": map[string]any{}}
				}
				tools = append(tools, toolDef{Type: "function", Function: fnDef{Name: t.Name, Description: t.Description, Parameters: params}})
			}
			call = func(name string, args map[string]any) (string, error) {
				intent, _ := args["_delegent_intent"].(string)
				delete(args, "_delegent_intent")
				return s.Call(ctx, name, args, intent, c.Status)
			}
		}
		for step := 0; step < o.MaxSteps; step++ {
			c.Status(fmt.Sprintf("thinking with %s (step %d)", o.Model, step+1))
			reply, err := chat(ctx, o, msgs, tools)
			if err != nil {
				return "", err
			}
			msgs = append(msgs, *reply)
			if len(reply.ToolCalls) == 0 {
				return strings.TrimSpace(reply.Content), nil
			}
			for _, tc := range reply.ToolCalls {
				name := tc.Function.Name
				args := map[string]any{}
				for k, v := range tc.Function.Arguments {
					args[k] = v
				}
				d.Logf("model calls %s %v", name, args)
				out, err := call(name, args)
				if err != nil {
					out = "ERROR: " + err.Error() + " (do not retry this tool; tell the user)"
				}
				msgs = append(msgs, chatMsg{Role: "tool", Content: out, ToolName: name})
			}
		}
		return "", fmt.Errorf("the model did not finish within %d steps", o.MaxSteps)
	}
}

type chatMsg struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolName  string     `json:"tool_name,omitempty"`
	ToolCalls []toolCall `json:"tool_calls,omitempty"`
}

type toolCall struct {
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

type toolDef struct {
	Type     string `json:"type"`
	Function fnDef  `json:"function"`
}

type fnDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  any    `json:"parameters"`
}

func chat(ctx context.Context, o OllamaOpts, msgs []chatMsg, tools []toolDef) (*chatMsg, error) {
	options := map[string]any{"temperature": 0.2}
	if o.NumCtx > 0 {
		options["num_ctx"] = o.NumCtx
	}
	body := map[string]any{"model": o.Model, "messages": msgs, "stream": false, "options": options, "think": o.Think}
	if len(tools) > 0 {
		body["tools"] = tools
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.URL, "/")+"/api/chat", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 10 * time.Minute}
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama %s: %s", res.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Message chatMsg `json:"message"`
		Error   string  `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}
	if out.Error != "" {
		return nil, fmt.Errorf("ollama: %s", out.Error)
	}
	return &out.Message, nil
}
