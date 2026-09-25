package gateway

// The native A2A surface: Delegent serves each fronted agent's card at its own address, with
// the URL pointing here and the auth a Delegent key, and speaks message/send and tasks/get
// for it. An agent whose engineers wrote it with an A2A client keeps that client: it changes
// the peer's URL to Delegent's, its bearer to its Delegent key, echoes X-Delegent-Session,
// and nothing else. Every message takes the same guarded path a tool call takes — the skill
// classifies as its tool, consent opens on the caller's channel (the console, since an A2A
// caller has no dialog), lineage links the hop, receipts record it — and is forwarded to the
// real agent with the real secret.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/store"
)

// A2A JSON-RPC error codes (the spec's, plus one for "not an agent").
const (
	a2aErrParse         = -32700
	a2aErrInvalidReq    = -32600
	a2aErrMethod        = -32601
	a2aErrParams        = -32602
	a2aErrInternal      = -32603
	a2aErrTaskNotFound  = -32001
	a2aErrNotCancelable = -32002
	a2aErrUnsupported   = -32004
	a2aErrRefused       = -32010 // Delegent refused the call (policy, consent denied, depth)
)

// a2aConsentWait is how long an A2A message/send blocks for a human decision before the
// task is handed back in auth-required. Agents rarely retry on their own, so this is longer
// than the MCP console wait. DELEGENT_A2A_CONSENT_WAIT overrides it.
const defaultA2AConsentWait = 5 * time.Minute

func a2aConsentWaitFromEnv() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("DELEGENT_A2A_CONSENT_WAIT")); err == nil && d > 0 {
		return d
	}
	return defaultA2AConsentWait
}

// pendingTaskPrefix marks a synthetic task id Delegent hands an A2A caller while its consent
// is pending; tasks/get on it resumes the call once the human decided.
const pendingTaskPrefix = "delegent-pending-"

var consentIDRe = regexp.MustCompile(`request ([0-9a-f]{16,})`)

// a2aPending is a message/send parked on consent: enough to run it again on tasks/get.
type a2aPending struct {
	conn   string
	tool   string
	args   map[string]any
	intent string
	task   string         // the real task id, once the resumed call started one
	result map[string]any // the final reply, when the resumed call answered without a task
}

type a2aState struct {
	mu      sync.Mutex
	pending map[string]a2aPending // consent id → the parked call
}

func (g *Gateway) a2aPendingStore() *a2aState {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	if g.a2a == nil {
		g.a2a = &a2aState{pending: map[string]a2aPending{}}
	}
	return g.a2a
}

// ServeA2A serves /a2a/{target}[/...]: the rewritten card (public, like any card), and the
// JSON-RPC endpoint (bearer = agent key, entitled on the target). Mount it at "/a2a/{target}"
// and "/a2a/{target}/{rest...}".
func (r *Registry) ServeA2A(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("target")
	if id == "" {
		http.NotFound(w, req)
		return
	}
	rest := strings.Trim(req.PathValue("rest"), "/")
	if req.Method == http.MethodGet && (rest == strings.TrimPrefix(a2a.WellKnownPath, "/") || rest == "agent-card.json") {
		r.serveA2ACard(w, req, id)
		return
	}
	if req.Method != http.MethodPost || rest != "" {
		http.NotFound(w, req)
		return
	}
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		g, err := r.a2aGateway(req.Context(), id)
		if err != nil {
			a2aHTTPError(w, err)
			return
		}
		g.serveA2ARPC(w, req)
	})
	if AuthRequired(r.st) {
		h = auth.RequireBearerToken(makeVerifier(r.st, id), &auth.RequireBearerTokenOptions{ResourceMetadataURL: ResourceMetadataURL(req)})(h)
	}
	h.ServeHTTP(w, req)
}

// ServeA2AIndex lists the agents this gateway fronts, with their Delegent addresses — the
// registry an A2A client discovers peers from. Bearer = agent key.
func (r *Registry) ServeA2AIndex(w http.ResponseWriter, req *http.Request) {
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ts, err := r.st.ListTargets(req.Context())
		if err != nil {
			http.Error(w, "gateway unavailable", http.StatusBadGateway)
			return
		}
		type entry struct {
			ID, Name, URL, Card string
			Skills              []a2a.Skill `json:"skills"`
		}
		var out []entry
		for _, t := range ts {
			if !t.Enabled || t.Kind != TargetKindA2A {
				continue
			}
			base := a2aBase(req) + "/a2a/" + t.ID
			e := entry{ID: t.ID, Name: t.Name, URL: base, Card: base + a2a.WellKnownPath}
			if g, err := r.a2aGateway(req.Context(), t.ID); err == nil {
				e.Skills = g.upstream.(*a2aUpstream).card.Skills
			}
			out = append(out, e)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": out})
	})
	if AuthRequired(r.st) {
		h = auth.RequireBearerToken(makeUserVerifier(r.st), &auth.RequireBearerTokenOptions{ResourceMetadataURL: ResourceMetadataURL(req)})(h)
	}
	h.ServeHTTP(w, req)
}

var errNotAgent = errors.New("target is not an A2A agent")

// a2aGateway resolves a built gateway that fronts an agent.
func (r *Registry) a2aGateway(ctx context.Context, id string) (*Gateway, error) {
	inst, err := r.get(ctx, id)
	if err != nil {
		return nil, err
	}
	g, ok := inst.(*Gateway)
	if !ok {
		return nil, errors.New("gateway unavailable")
	}
	if _, ok := g.upstream.(*a2aUpstream); !ok {
		return nil, errNotAgent
	}
	return g, nil
}

func a2aHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, errDisabled), errors.Is(err, errNotAgent):
		http.NotFound(w, nil)
	default:
		log.Printf("[delegent] a2a: gateway failed to build: %v", err)
		http.Error(w, "gateway unavailable", http.StatusBadGateway)
	}
}

// a2aBase is this gateway's externally visible origin, from the request (behind a tunnel or
// proxy it is whatever the client used).
func a2aBase(req *http.Request) string {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if p := req.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + req.Host
}

// serveA2ACard serves the agent's card rewritten for callers that come through Delegent: the
// URL is this endpoint, the auth is a Delegent key, streaming is off (long tasks are polled).
func (r *Registry) serveA2ACard(w http.ResponseWriter, req *http.Request, id string) {
	g, err := r.a2aGateway(req.Context(), id)
	if err != nil {
		a2aHTTPError(w, err)
		return
	}
	card := *g.upstream.(*a2aUpstream).card
	card.URL = a2aBase(req) + "/a2a/" + id
	card.Description = strings.TrimSpace(card.Description + " (via Delegent: every call is consent-gated and receipted; authenticate with a Delegent agent key)")
	card.Capabilities = a2a.Capabilities{}
	card.SecuritySchemes = map[string]a2a.SecurityScheme{"delegent": {Type: "http", Scheme: "bearer"}}
	card.Security = []map[string][]string{{"delegent": {}}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(card)
}

type a2aRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func a2aReply(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func a2aError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

// a2aConn is the synthetic connection id an A2A caller's grants live under: per key, so an
// agent keeps its grants across calls; the parent session (X-Delegent-Session) is folded in by
// connKey as for any caller.
func a2aConn(ctx context.Context) string {
	prefix, _, _ := keyIdentityFromContext(ctx)
	if prefix == "" {
		prefix = "anonymous"
	}
	return "a2a:" + prefix
}

// serveA2ARPC handles one JSON-RPC call from an A2A client.
func (g *Gateway) serveA2ARPC(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, 8<<20))
	if err != nil {
		a2aError(w, nil, a2aErrParse, "unreadable body")
		return
	}
	var rpc a2aRPCRequest
	if err := json.Unmarshal(body, &rpc); err != nil || rpc.Method == "" {
		a2aError(w, nil, a2aErrParse, "not a JSON-RPC request")
		return
	}
	ctx := withRawA2A(withConsentWait(req.Context(), a2aConsentWaitFromEnv()))
	conn := a2aConn(ctx)
	up := g.upstream.(*a2aUpstream)

	switch rpc.Method {
	case "message/send":
		var p struct {
			Message a2a.Message `json:"message"`
		}
		if err := json.Unmarshal(rpc.Params, &p); err != nil || len(p.Message.Parts) == 0 {
			a2aError(w, rpc.ID, a2aErrParams, "params.message with parts is required")
			return
		}
		text := a2a.PartsText(p.Message.Parts)
		intent := metaString(p.Message.Metadata, "_delegent_intent", "intent")
		if parentFromContext(ctx) == "" {
			if s := metaString(p.Message.Metadata, a2a.SessionMetaKey); s != "" {
				ctx = withParent(ctx, s)
				conn = a2aConn(ctx)
			}
		}
		var tool string
		args := map[string]any{}
		if p.Message.TaskID != "" {
			// an answer to a task the agent parked on input-required
			tool, args["task_id"], args["message"] = a2a.TaskTool, p.Message.TaskID, text
		} else {
			tool = up.skillTool(metaString(p.Message.Metadata, a2a.SkillMetaKey))
			if tool == "" {
				a2aError(w, rpc.ID, a2aErrParams, "this agent has several skills: name one in message.metadata.skill ("+strings.Join(up.skillIDs(), ", ")+")")
				return
			}
			args["message"] = text
			if p.Message.ContextID != "" {
				args["context_id"] = p.Message.ContextID
			}
		}
		g.a2aGuarded(ctx, w, rpc.ID, conn, tool, args, intent)

	case "tasks/get":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rpc.Params, &p); err != nil || p.ID == "" {
			a2aError(w, rpc.ID, a2aErrParams, "params.id is required")
			return
		}
		if strings.HasPrefix(p.ID, pendingTaskPrefix) {
			g.a2aResumePending(ctx, w, rpc.ID, conn, p.ID)
			return
		}
		g.a2aGuarded(ctx, w, rpc.ID, conn, a2a.TaskTool, map[string]any{"task_id": p.ID}, "")

	case "tasks/cancel":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rpc.Params, &p); err != nil || p.ID == "" {
			a2aError(w, rpc.ID, a2aErrParams, "params.id is required")
			return
		}
		// Cancelling is allowed to whoever holds a live session on this target — the same
		// party whose call started the task.
		if g.resumeSession(g.connKey(ctx, conn)) == "" {
			a2aError(w, rpc.ID, a2aErrRefused, "no live session on this agent — nothing of yours to cancel")
			return
		}
		res, err := up.client.CancelTask(ctx, p.ID, g.resumeSession(g.connKey(ctx, conn)))
		if err != nil {
			a2aError(w, rpc.ID, a2aErrNotCancelable, err.Error())
			return
		}
		a2aReply(w, rpc.ID, rawA2A(res))

	case "message/stream", "tasks/resubscribe":
		a2aError(w, rpc.ID, a2aErrUnsupported, "streaming is not offered through Delegent — use message/send and poll tasks/get")

	default:
		a2aError(w, rpc.ID, a2aErrMethod, "method not found: "+rpc.Method)
	}
}

// a2aGuarded runs one call through the guarded path and answers the JSON-RPC accordingly:
// the agent's task or message on success; an auth-required task while consent is pending; a
// refusal error otherwise.
func (g *Gateway) a2aGuarded(ctx context.Context, w http.ResponseWriter, rpcID json.RawMessage, conn, tool string, args map[string]any, intent string) {
	raw, _ := json.Marshal(args)
	res, err := g.guardedCall(ctx, conn, nil, tool, args, intent, raw)
	if err != nil {
		a2aError(w, rpcID, a2aErrInternal, err.Error())
		return
	}
	if task := rawA2AFromResult(res); task != nil {
		a2aReply(w, rpcID, task)
		return
	}
	text := toolResultText(res)
	if id := consentIDRe.FindStringSubmatch(text); id != nil && strings.Contains(text, "PENDING") {
		// Parked on the human: hand back a task in auth-required whose id resumes the call.
		st := g.a2aPendingStore()
		st.mu.Lock()
		st.pending[id[1]] = a2aPending{conn: conn, tool: tool, args: args, intent: intent}
		st.mu.Unlock()
		a2aReply(w, rpcID, pendingTask(id[1], text))
		return
	}
	if res.IsError {
		a2aError(w, rpcID, a2aErrRefused, text)
		return
	}
	// A grant that landed in-turn returns "granted … retry": run the call again now.
	if strings.Contains(text, "granted access") {
		res, err = g.guardedCall(ctx, conn, nil, tool, args, intent, raw)
		if err == nil {
			if task := rawA2AFromResult(res); task != nil {
				a2aReply(w, rpcID, task)
				return
			}
		}
	}
	a2aError(w, rpcID, a2aErrInternal, "unexpected gateway reply: "+text)
}

// a2aResumePending answers tasks/get on a pending-consent id: still pending → the same
// auth-required task; denied → rejected; approved → the call runs and its real task answers,
// under the pending id the caller knows.
func (g *Gateway) a2aResumePending(ctx context.Context, w http.ResponseWriter, rpcID json.RawMessage, conn, pendingID string) {
	consentID := strings.TrimPrefix(pendingID, pendingTaskPrefix)
	st := g.a2aPendingStore()
	st.mu.Lock()
	pc, ok := st.pending[consentID]
	st.mu.Unlock()
	if !ok || pc.conn != conn {
		a2aError(w, rpcID, a2aErrTaskNotFound, "unknown task "+pendingID)
		return
	}
	if pc.result != nil {
		a2aReply(w, rpcID, aliasTask(pc.result, pendingID))
		return
	}
	if pc.task != "" {
		// already resumed: report the real task under the id the caller holds
		res, err := g.guardedCall(ctx, conn, nil, a2a.TaskTool, map[string]any{"task_id": pc.task}, "", nil)
		if err == nil {
			if task := rawA2AFromResult(res); task != nil {
				a2aReply(w, rpcID, aliasTask(task, pendingID))
				return
			}
		}
		a2aError(w, rpcID, a2aErrInternal, "could not read task "+pc.task)
		return
	}
	if g.st != nil {
		if row, err := g.st.GetConsentRequest(ctx, consentID); err == nil {
			switch row.Status {
			case "pending":
				a2aReply(w, rpcID, pendingTask(consentID, "waiting for the operator to approve "+pc.tool))
				return
			case "denied", "expired", "cancelled":
				a2aReply(w, rpcID, a2a.Task{Kind: "task", ID: pendingID, Status: a2a.TaskStatus{State: a2a.StateRejected, Timestamp: nowRFC3339(),
					Message: &a2a.Message{Kind: "message", Role: "agent", MessageID: pendingID + "-status", Parts: []a2a.Part{a2a.TextPart("Delegent: the operator " + row.Status + " this request")}}}})
				return
			}
		}
	}
	// approved (or no durable row to consult): run the call; the grant is bound to this conn
	raw, _ := json.Marshal(pc.args)
	res, err := g.guardedCall(withRawA2A(ctx), conn, nil, pc.tool, pc.args, pc.intent, raw)
	if err != nil {
		a2aError(w, rpcID, a2aErrInternal, err.Error())
		return
	}
	task := rawA2AFromResult(res)
	if task == nil {
		if text := toolResultText(res); strings.Contains(text, "PENDING") {
			a2aReply(w, rpcID, pendingTask(consentID, text))
			return
		} else {
			a2aError(w, rpcID, a2aErrRefused, text)
			return
		}
	}
	st.mu.Lock()
	if id, _ := task["id"].(string); id != "" {
		pc.task = id
	} else {
		pc.result = task // an immediate message reply: keep it, never re-send the request
	}
	st.pending[consentID] = pc
	st.mu.Unlock()
	a2aReply(w, rpcID, aliasTask(task, pendingID))
}

func pendingTask(consentID, note string) a2a.Task {
	return a2a.Task{Kind: "task", ID: pendingTaskPrefix + consentID, Status: a2a.TaskStatus{State: a2a.StateAuthRequired, Timestamp: nowRFC3339(),
		Message: &a2a.Message{Kind: "message", Role: "agent", MessageID: pendingTaskPrefix + consentID + "-status", Parts: []a2a.Part{a2a.TextPart("Delegent: a human must approve this call. Poll tasks/get with this task id; it resumes once approved. " + note)}}}}
}

// aliasTask presents a real task under the pending id the caller holds.
func aliasTask(task map[string]any, id string) map[string]any {
	out := make(map[string]any, len(task))
	for k, v := range task {
		out[k] = v
	}
	out["id"] = id
	return out
}

func metaString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// --- raw A2A results through the guarded path ---

type rawA2AKey struct{}

// withRawA2A asks the A2A upstream to attach the agent's own task/message JSON to the tool
// result (in _meta), so the A2A surface can answer with the real object, not the flattened text.
func withRawA2A(ctx context.Context) context.Context {
	return context.WithValue(ctx, rawA2AKey{}, true)
}

func wantsRawA2A(ctx context.Context) bool { v, _ := ctx.Value(rawA2AKey{}).(bool); return v }

const rawA2AMeta = "delegent/a2a"

// rawA2A is the agent's task or message as a JSON object.
func rawA2A(res *a2a.Result) map[string]any {
	var v any
	switch {
	case res == nil:
		return nil
	case res.Task != nil:
		v = res.Task
	case res.Message != nil:
		v = res.Message
	default:
		return nil
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func rawA2AFromResult(res *mcp.CallToolResult) map[string]any {
	if res == nil || res.Meta == nil {
		return nil
	}
	m, _ := res.Meta[rawA2AMeta].(map[string]any)
	return m
}

// --- consent wait override ---

type consentWaitKey struct{}

// withConsentWait lets a surface choose how long a console-consent block waits in-turn.
func withConsentWait(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, consentWaitKey{}, d)
}

func consentWaitFromContext(ctx context.Context) time.Duration {
	d, _ := ctx.Value(consentWaitKey{}).(time.Duration)
	return d
}
