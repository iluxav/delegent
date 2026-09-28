package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"delegent.dev/gateway/a2a"
)

// The playground: the dashboard runs a fronted agent as the operator's own client. The call
// goes through the same A2A surface an outside client would use — the same guarded path, the
// same consent, the same receipts — but in-process, under a per-run identity that carries no
// key: the operator is a person, and a person's client sees everything. Every playground run
// is its own conversation (its own connection id), so the Runs page shows it as one run.

// PlaygroundSkill is one skill of an agent's card as the playground offers it.
type PlaygroundSkill struct {
	ID, Name, Description string
	Examples              []string
}

// PlaygroundSkills lists the skills of agent target id, from its card.
func (r *Registry) PlaygroundSkills(ctx context.Context, id string) ([]PlaygroundSkill, error) {
	g, err := r.a2aGateway(ctx, id)
	if err != nil {
		return nil, err
	}
	up := g.upstream.(*a2aUpstream)
	var out []PlaygroundSkill
	for _, sk := range up.card.Skills {
		out = append(out, PlaygroundSkill{ID: sk.ID, Name: sk.Name, Description: sk.Description, Examples: sk.Examples})
	}
	return out, nil
}

// PlaygroundConn is the connection id a playground run's events carry — what the Runs page
// looks the run up by.
func PlaygroundConn(nonce string) string { return "a2a:play-" + nonce }

// PlaygroundSend sends one message to agent target id's skill as user's playground client and
// waits for the outcome: the agent's reply text (or its task's state when the task is still
// working), or an error when Delegent refused the call or the agent failed. Consent is
// awaited in-line for up to the A2A consent wait, like any A2A caller's.
func (r *Registry) PlaygroundSend(ctx context.Context, user, id, nonce, skill, message, intent string) (string, error) {
	g, err := r.a2aGateway(ctx, id)
	if err != nil {
		return "", err
	}
	ent, err := r.st.GetEntitlement(ctx, user, id)
	if err != nil {
		return "", fmt.Errorf("%s is not entitled on %s", user, id)
	}
	meta := map[string]any{a2a.SkillMetaKey: skill}
	if intent != "" {
		meta["_delegent_intent"] = intent
	}
	rpc, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "message/send",
		"params": map[string]any{"message": a2a.Message{Kind: "message", Role: "user", MessageID: "play-" + nonce, Parts: []a2a.Part{a2a.TextPart(message)}, Metadata: meta}},
	})
	// The per-run identity, threaded the way a verified bearer would be: no key id (nothing
	// is remembered for a playground run), the key name every event and lifeline shows, and a
	// prefix that makes the connection id unique to this run.
	verifier := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{
			UserID: user, Scopes: ent.Effective(), Expiration: time.Now().Add(time.Hour),
			Extra: map[string]any{"user": user, "key_name": "playground", "key_prefix": "play-" + nonce, "remote_ip": "dashboard"},
		}, nil
	}
	req := httptest.NewRequest(http.MethodPost, "/a2a/"+id, bytes.NewReader(rpc)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer playground")
	rec := httptest.NewRecorder()
	auth.RequireBearerToken(verifier, nil)(http.HandlerFunc(g.serveA2ARPC)).ServeHTTP(rec, req)

	var res struct {
		Result map[string]any `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		return "", fmt.Errorf("the agent's answer was not JSON-RPC (%d): %s", rec.Code, rec.Body.String())
	}
	if res.Error != nil {
		return "", errors.New(res.Error.Message)
	}
	return playgroundText(res.Result), nil
}

// playgroundText renders an A2A result — a message, or a task with its status and artifacts —
// as the text the playground shows.
func playgroundText(res map[string]any) string {
	raw, _ := json.Marshal(res)
	switch res["kind"] {
	case "message":
		var m a2a.Message
		if json.Unmarshal(raw, &m) == nil {
			return a2a.PartsText(m.Parts)
		}
	case "task":
		var t a2a.Task
		if json.Unmarshal(raw, &t) == nil {
			var parts []a2a.Part
			for _, art := range t.Artifacts {
				parts = append(parts, art.Parts...)
			}
			if txt := a2a.PartsText(parts); txt != "" {
				return txt
			}
			if t.Status.Message != nil {
				if txt := a2a.PartsText(t.Status.Message.Parts); txt != "" {
					return txt
				}
			}
			return "task " + t.ID + " is " + t.Status.State
		}
	}
	return string(raw)
}
