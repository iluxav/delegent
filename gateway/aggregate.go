package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/store"
)

// aggResultText flattens a tool result's text content for fan-out concatenation.
func aggResultText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// aggSep joins target id and tool name in the aggregate's namespaced tool names
// ("gh__create_issue"). Double underscore stays inside the client-enforced tool-name charset
// and is unlikely inside real target ids/tool names.
const aggSep = "__"

// aggRoute is where one namespaced aggregate tool goes.
type aggRoute struct {
	targetID string
	tool     string
}

// Aggregate is ONE user's whole Delegent on a single MCP endpoint (/mcp): every entitled,
// enabled target's tools, namespaced "<target>__<tool>", routed to the per-target gateways.
// Authority is NOT aggregated — sessions, scopes, budgets, and consent all stay target-scoped
// inside the routed gateway; the aggregate only fans the one client connection out. Built per
// user (the tool list IS the user's entitlements) and dropped whenever any target changes.
type Aggregate struct {
	user    string
	reg     *Registry
	server  *mcp.Server
	handler http.Handler
	routes  map[string]aggRoute
	targets []string // included target ids, sorted

	mu         sync.Mutex
	byConnCaps map[string]clientCaps
	lastTarget map[string]string // connID → target of the last routed call (entry-tool inference)
}

// newAggregate assembles the user's aggregate: entitled+enabled targets only. A target whose
// gateway fails to build is SKIPPED (logged) — one broken vendor must not take down the rest.
func newAggregate(ctx context.Context, r *Registry, userID string) (*Aggregate, error) {
	ts, err := r.st.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })

	a := &Aggregate{
		user: userID, reg: r,
		routes:     map[string]aggRoute{},
		byConnCaps: map[string]clientCaps{},
		lastTarget: map[string]string{},
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "delegent", Version: "0.2.0"}, &mcp.ServerOptions{
		Instructions: "Delegent fronts ALL your connected services on this one endpoint. Tools are named <service>__<tool>. " +
			"Each service gates its tools behind human consent: call plan_access to see what a service can grant " +
			"(pass {\"target\": <service>} to pick one), then request_access for the subset your task needs — " +
			"one approval instead of a prompt per tool.",
		InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
			caps := clientCaps{}
			name, version := "unknown", ""
			if ip := req.Session.InitializeParams(); ip != nil {
				if ip.ClientInfo != nil {
					name, version = ip.ClientInfo.Name, ip.ClientInfo.Version
				}
				if ip.Capabilities != nil {
					caps.elicitation = ip.Capabilities.Elicitation != nil
					_, caps.uiExt = ip.Capabilities.Extensions[uiExtensionKey]
				}
			}
			a.setCaps(req.Session.ID(), caps)
			log.Printf("[delegent] client connected to AGGREGATE as %s: %s %s | elicitation=%v ui=%v | targets: %s",
				userID, name, version, caps.elicitation, caps.uiExt, strings.Join(a.targets, ", "))
		},
	})

	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		if _, err := r.st.GetEntitlement(ctx, userID, t.ID); err != nil {
			continue // not this user's target
		}
		inst, err := r.get(ctx, t.ID)
		if err != nil {
			log.Printf("[delegent] aggregate for %s: target %q unavailable (%v) — skipped", userID, t.ID, err)
			continue
		}
		g, ok := inst.(*Gateway)
		if !ok {
			continue
		}
		for _, vt := range g.vendorToolInfos {
			ns := t.ID + aggSep + vt.Name
			a.routes[ns] = aggRoute{targetID: t.ID, tool: vt.Name}
			schema := vt.InputSchema
			if schema == nil {
				schema = withIntentField(nil) // the SDK requires a schema; degrade to intent-only
			}
			s.AddTool(&mcp.Tool{
				Name:        ns,
				Description: "[" + t.ID + "] " + vt.Description,
				InputSchema: schema,
			}, a.vendorTool(t.ID, vt.Name))
		}
		a.targets = append(a.targets, t.ID)
	}

	a.addEntryTools(s)
	a.server = s
	a.handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	log.Printf("[delegent] aggregate for %s up: %d targets, %d tools", userID, len(a.targets), len(a.routes))
	return a, nil
}

func (a *Aggregate) setCaps(connID string, c clientCaps) {
	a.mu.Lock()
	a.byConnCaps[connID] = c
	a.mu.Unlock()
}

func (a *Aggregate) noteTarget(connID, targetID string) {
	a.mu.Lock()
	a.lastTarget[connID] = targetID
	a.mu.Unlock()
}

// resolveTarget picks the target an entry tool (request_access, …) applies to: an explicit
// {"target": …} argument wins; else the target of this connection's last routed call; else a
// lone target is unambiguous. Anything else is an error naming the choices — never a guess.
func (a *Aggregate) resolveTarget(connID, explicit string) (string, string) {
	if explicit != "" {
		for _, t := range a.targets {
			if t == explicit {
				return t, ""
			}
		}
		return "", "unknown target " + fmt.Sprintf("%q", explicit) + " — connected targets: " + strings.Join(a.targets, ", ")
	}
	a.mu.Lock()
	last := a.lastTarget[connID]
	a.mu.Unlock()
	if last != "" {
		return last, ""
	}
	if len(a.targets) == 1 {
		return a.targets[0], ""
	}
	return "", "several services are connected (" + strings.Join(a.targets, ", ") + ") — pass {\"target\": <service>} to pick one"
}

// gateway resolves the live per-target gateway at CALL time (never cached in a closure), so a
// console-side invalidate/rebuild is picked up transparently.
func (a *Aggregate) gateway(ctx context.Context, targetID string) (*Gateway, error) {
	inst, err := a.reg.get(ctx, targetID)
	if err != nil {
		return nil, err
	}
	g, ok := inst.(*Gateway)
	if !ok {
		return nil, errors.New("target gateway unavailable")
	}
	return g, nil
}

// prepareCall makes the target gateway see this aggregate connection exactly as a direct one:
// the client caps captured at the aggregate initialize and the key's consent-channel policy
// (from the verified TokenInfo) are copied under the SAME connection id the routed handlers
// will read, and the routing is noted for entry-tool target inference.
func (a *Aggregate) prepareCall(ctx context.Context, connID, targetID string, g *Gateway) {
	a.mu.Lock()
	caps := a.byConnCaps[connID]
	a.mu.Unlock()
	g.setCaps(connID, caps)
	g.setPolicy(connID, channelPolicyFromContext(ctx))
	a.noteTarget(connID, targetID)
}

// vendorTool routes one namespaced tool call into its target gateway's own handler — consent,
// sessions, receipts, and events all run inside that gateway, identical to a direct connection.
func (a *Aggregate) vendorTool(targetID, tool string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			return toolError("🔌 DELEGENT: target " + targetID + " is unavailable: " + err.Error()), nil
		}
		a.prepareCall(ctx, req.Session.ID(), targetID, g)
		return g.vendorTool(tool)(ctx, req)
	}
}

// --- entry tools: one set for the whole aggregate, routed by target inference ---

type aggAccessArgs struct {
	Scopes []string `json:"scopes" jsonschema:"scopes to pre-grant, e.g. [\"files:read\",\"files:write\"]"`
	Reason string   `json:"reason" jsonschema:"why the task needs this access"`
	Target string   `json:"target,omitempty" jsonschema:"which connected service this applies to (omit after calling one of its tools)"`
}

type aggPlanArgs struct {
	Task   string `json:"task,omitempty" jsonschema:"what you are trying to do (optional, for your own planning)"`
	Target string `json:"target,omitempty" jsonschema:"plan for one service only (default: all)"`
}

type aggRevokeArgs struct {
	Chain bool `json:"chain,omitempty" jsonschema:"also revoke sub-agent sessions this connection minted"`
}

func (a *Aggregate) addEntryTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "plan_access",
		Description: "Plan your access up front, across every connected service (or one, with {\"target\": …}). Returns the grantable capabilities per service. Call BEFORE using tools, then request_access for the subset your task needs.",
	}, a.handlePlanAccess)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "request_access",
		Description: "Request one or more capabilities (scopes) on a connected service in a single approval. The service is inferred from your last tool call, or pass {\"target\": …}.",
	}, a.handleRequestAccess)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "open_access_dialog",
		Description: "Show the access-request dialog. FOR HOSTS THAT RENDER UI WIDGETS ONLY (e.g. Claude Desktop) — most clients should use request_access instead. Called when a consent-required message tells you to.",
		Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": consentWidgetURI}},
	}, a.handleOpenAccessDialog)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "submit_consent_decision",
		Description: "Submit the user's GRANT/DENY decision from the Delegent consent dialog. App-only: called by the consent widget, never by the model.",
		Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": consentWidgetURI, "visibility": []string{"app"}}},
	}, a.handleSubmitConsent)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "receipts",
		Description: "Return the audit trail of every access decision Delegent has made across your connected services.",
	}, a.handleReceipts)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "revoke",
		Description: "Drop the access this connection holds on ALL connected services — the next tool call must re-consent.",
	}, a.handleRevoke)
	s.AddResource(&mcp.Resource{
		URI: consentWidgetURI, Name: "delegent-consent", Title: "Delegent consent dialog",
		Description: "The GRANT/DENY consent dialog MCP Apps-capable hosts render in-chat for request_access.",
		MIMEType:    consentWidgetMIME,
	}, serveConsentWidget)
	s.AddResource(&mcp.Resource{
		URI: consentTokenURI, Name: "delegent-consent-token",
		Description: "Widget-only token recovery for hosts that strip _meta from tool-result notifications.",
		MIMEType:    "application/json",
	}, a.serveConsentToken)
}

// routedGateway resolves + prepares the gateway an entry tool applies to, or returns the
// error result to hand the model.
func (a *Aggregate) routedGateway(ctx context.Context, req *mcp.CallToolRequest, explicit string) (*Gateway, *mcp.CallToolResult) {
	target, errText := a.resolveTarget(req.Session.ID(), explicit)
	if errText != "" {
		return nil, toolError("DELEGENT: " + errText)
	}
	g, err := a.gateway(ctx, target)
	if err != nil {
		return nil, toolError("🔌 DELEGENT: target " + target + " is unavailable: " + err.Error())
	}
	a.prepareCall(ctx, req.Session.ID(), target, g)
	return g, nil
}

func (a *Aggregate) handleRequestAccess(ctx context.Context, req *mcp.CallToolRequest, args aggAccessArgs) (*mcp.CallToolResult, any, error) {
	g, errRes := a.routedGateway(ctx, req, args.Target)
	if errRes != nil {
		return errRes, nil, nil
	}
	return g.handleRequestAccess(ctx, req, requestAccessArgs{Scopes: args.Scopes, Reason: args.Reason})
}

func (a *Aggregate) handleOpenAccessDialog(ctx context.Context, req *mcp.CallToolRequest, args aggAccessArgs) (*mcp.CallToolResult, any, error) {
	g, errRes := a.routedGateway(ctx, req, args.Target)
	if errRes != nil {
		return errRes, nil, nil
	}
	return g.handleOpenAccessDialog(ctx, req, requestAccessArgs{Scopes: args.Scopes, Reason: args.Reason})
}

// handleSubmitConsent routes by the pending request id — the widget knows the id but not the
// target, so scan the included targets' live pending stores for its owner.
func (a *Aggregate) handleSubmitConsent(ctx context.Context, req *mcp.CallToolRequest, args submitConsentArgs) (*mcp.CallToolResult, any, error) {
	for _, targetID := range a.targets {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			continue
		}
		for _, pc := range g.pending.listLive() {
			if pc.ID == args.RequestID {
				a.prepareCall(ctx, req.Session.ID(), targetID, g)
				return g.handleSubmitConsent(ctx, req, args)
			}
		}
	}
	return toolError("DELEGENT: unknown or expired consent request " + args.RequestID), nil, nil
}

func (a *Aggregate) handlePlanAccess(ctx context.Context, req *mcp.CallToolRequest, args aggPlanArgs) (*mcp.CallToolResult, any, error) {
	targets := a.targets
	if args.Target != "" {
		t, errText := a.resolveTarget(req.Session.ID(), args.Target)
		if errText != "" {
			return toolError("DELEGENT: " + errText), nil, nil
		}
		targets = []string{t}
	}
	var parts []string
	structured := map[string]any{}
	for _, targetID := range targets {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			parts = append(parts, "== "+targetID+" ==\nunavailable: "+err.Error())
			continue
		}
		a.prepareCall(ctx, req.Session.ID(), targetID, g)
		res, st, err := g.handlePlanAccess(ctx, req, planAccessArgs{Task: args.Task})
		if err != nil || res == nil {
			continue
		}
		parts = append(parts, "== "+targetID+" ==\n"+aggResultText(res))
		structured[targetID] = st
	}
	return text(strings.Join(parts, "\n\n")), structured, nil
}

func (a *Aggregate) handleReceipts(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	var parts []string
	structured := map[string]any{}
	for _, targetID := range a.targets {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			continue
		}
		res, st, err := g.handleReceipts(ctx, req, struct{}{})
		if err != nil || res == nil {
			continue
		}
		parts = append(parts, "== "+targetID+" ==\n"+aggResultText(res))
		structured[targetID] = st
	}
	return text(strings.Join(parts, "\n\n")), structured, nil
}

func (a *Aggregate) handleRevoke(ctx context.Context, req *mcp.CallToolRequest, args aggRevokeArgs) (*mcp.CallToolResult, any, error) {
	var parts []string
	for _, targetID := range a.targets {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			continue
		}
		res, _, err := g.handleRevoke(ctx, req, revokeArgs{Chain: args.Chain})
		if err != nil || res == nil {
			continue
		}
		parts = append(parts, targetID+": "+aggResultText(res))
	}
	return text(strings.Join(parts, "\n")), nil, nil
}

// serveConsentToken serves the widget token-recovery resource by scanning the included
// targets for the connection's latest pending record (same contract as the per-target one).
func (a *Aggregate) serveConsentToken(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	for _, targetID := range a.targets {
		g, err := a.gateway(ctx, targetID)
		if err != nil {
			continue
		}
		if res, err := g.serveConsentToken(ctx, req); err == nil {
			return res, nil
		}
	}
	return nil, errors.New("no pending consent for this connection")
}

// --- registry side ---

// makeUserVerifier authenticates an agent key WITHOUT binding to one target — the aggregate
// spans all the key's user's targets; per-target entitlement is enforced by the aggregate's
// own membership (and the routed gateway's control plane) instead.
func makeUserVerifier(st store.Store) auth.TokenVerifier {
	return func(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
		k, err := st.GetAgentKeyByHash(ctx, agentkey.Hash(token))
		if err != nil {
			log.Printf("[delegent] token rejected: unknown key: %v", err)
			return nil, auth.ErrInvalidToken
		}
		if k.RevokedAt != 0 {
			log.Printf("[delegent] token rejected: key %s revoked", k.ID)
			return nil, auth.ErrInvalidToken
		}
		go func() { _ = st.TouchAgentKey(context.Background(), k.ID, nowMillis()) }()
		return &auth.TokenInfo{
			UserID:     k.UserID,
			Expiration: time.Now().AddDate(100, 0, 0), // agent keys don't expire; they're revoked
			Extra: map[string]any{
				"user":             k.UserID,
				"key_prefix":       k.Prefix,
				"key_name":         k.Name,
				"remote_ip":        remoteIP(r),
				"consent_channels": k.ConsentChannels,
			},
		}, nil
	}
}

// ServeAggregate serves the user-wide endpoint (mount at /mcp and /mcp/{$}): verify the key,
// then lazily build (and cache) that user's aggregate. In no-auth dev mode the deployment's
// first user stands in (the routed gateways fall back to their own default principal, matching
// the per-target dev posture).
func (r *Registry) ServeAggregate(w http.ResponseWriter, req *http.Request) {
	if AuthRequired(r.st) {
		auth.RequireBearerToken(makeUserVerifier(r.st), &auth.RequireBearerTokenOptions{})(
			http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				user := ""
				if ti := auth.TokenInfoFromContext(req.Context()); ti != nil {
					user = ti.UserID
				}
				r.serveAggregateAs(w, req, user)
			})).ServeHTTP(w, req)
		return
	}
	us, err := r.st.ListUsers(req.Context())
	if err != nil || len(us) == 0 {
		http.Error(w, "no users provisioned", http.StatusServiceUnavailable)
		return
	}
	r.serveAggregateAs(w, req, us[0].ID)
}

func (r *Registry) serveAggregateAs(w http.ResponseWriter, req *http.Request, user string) {
	a, err := r.aggregateFor(req.Context(), user)
	if err != nil {
		log.Printf("[delegent] aggregate for %q failed to build: %v", user, err)
		http.Error(w, "gateway unavailable", http.StatusBadGateway)
		return
	}
	a.handler.ServeHTTP(w, req)
}

// ServeStdio runs userID's aggregate MCP server over stdin/stdout — the same surface /mcp
// serves over HTTP, on MCP's native local transport. The caller authenticates the agent key
// and resolves userID BEFORE calling (stdio has no bearer-token middleware); inside the
// engine the per-target gateways then act for their default principal — the target owner —
// which in a single-operator deployment is the same user. Blocks until ctx is cancelled or
// the client closes stdin.
func (r *Registry) ServeStdio(ctx context.Context, userID string) error {
	a, err := r.aggregateFor(ctx, userID)
	if err != nil {
		return err
	}
	return a.server.Run(ctx, &mcp.StdioTransport{})
}

// aggregateFor returns the cached per-user aggregate, building it on first use.
func (r *Registry) aggregateFor(ctx context.Context, userID string) (*Aggregate, error) {
	if userID == "" {
		return nil, errors.New("no user identity on the connection")
	}
	r.mu.Lock()
	if a, ok := r.aggregates[userID]; ok {
		r.mu.Unlock()
		return a, nil
	}
	r.mu.Unlock()
	a, err := newAggregate(ctx, r, userID)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prior, ok := r.aggregates[userID]; ok {
		return prior, nil // lost a benign build race — keep the first
	}
	r.aggregates[userID] = a
	return a, nil
}

// dropAggregates discards every cached aggregate — called on any target invalidation, since an
// aggregate's tool list mirrors the target set. Rebuilt lazily on the next request; connected
// clients see a session-not-found and re-initialize, same contract as per-target invalidation.
func (r *Registry) dropAggregates() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aggregates = map[string]*Aggregate{}
}
