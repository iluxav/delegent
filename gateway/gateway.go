// Package gateway is Delegent's transparent MCP gateway as a library: one Gateway instance
// fronts ONE target — the agent connects to it as if it were the vendor, sees the vendor's
// real tools by name, and each call is authorized against the caller's session before being
// forwarded upstream with the vendor credential the agent never sees. Access is requested ON
// DEMAND via MCP elicitation; a spending call is additionally charged against the session's
// budget. All session/receipt/escalation state persists through the store.Store, so a rebuild
// (or restart) rehydrates live grants instead of re-consenting.
//
// A Gateway is served over HTTP by mounting Handler() (cmd/api mounts one per target at
// /mcp/{target} via the Registry), or over stdio with Run() (cmd/delegent's dev mode).
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/broker"
	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/loader"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
	core "delegent.dev/protocol"
)

// Gateway serves one target: its adapter/advisor, control plane, broker, the connected
// upstream MCP session, and the per-connection session map.
type Gateway struct {
	targetID string
	adapter  core.Adapter
	cp       *controlplane.ControlPlane
	br       *broker.Broker
	st       store.Store // persistence for durable console consent requests (nil in unit tests)
	upstream *mcp.ClientSession
	server   *mcp.Server
	handler  http.Handler

	sessMu       sync.Mutex
	byConn       map[string]string     // MCP connection ID -> the caller's accumulating session handle
	byConnCaps   map[string]clientCaps // MCP connection ID -> what the client declared at initialize
	byConnMeta   map[string]callMeta   // MCP connection ID -> the callMeta of the last guarded call (for the widget headline)
	byConnPolicy map[string][]string   // MCP connection ID -> the agent key's consent-channel policy (empty = auto)

	// pending holds widget-mode consent asks awaiting the human's decision — single-use,
	// short-TTL nonces redeemed by submit_consent_decision.
	pending *pendingStore

	// notifier, when set (wired by the Registry), is pinged after a console consent request is
	// durably parked, so out-of-band channels (telegram, …) can alert the owner. Best-effort
	// and advisory only — it never gates or grants anything.
	notifier ConsentNotifier

	// vendorToolInfos is the vendor tool list as registered on this gateway's server (name,
	// description, schema WITH the intent field) — the aggregate reads it to build its
	// namespaced union without a second upstream ListTools.
	vendorToolInfos []*mcp.Tool

	// defaultPrincipal is the operating identity when no agent key is presented (dev/no-auth):
	// the target's owner. With a key, the connection operates as the key's user instead.
	defaultPrincipal string

	// grantScope is DELEGENT_GRANT_SCOPE, read ONCE at construction: "connection" (default)
	// binds every grant to the MCP connection that earned it; "user" restores the old
	// user-wide resume (any new connection picks up the principal's latest live session).
	grantScope string

	// flags are FF_* test toggles read once at construction (force-disable a consent channel).
	flags featureFlags

	// consoleConsent (DELEGENT_CONSOLE_CONSENT, default ON) enables the console consent channel:
	// a client that can neither elicit nor render the widget parks a pending request and a human
	// GRANTs it in the web console instead of failing closed. Off restores hard fail-closed.
	consoleConsent bool
	// syncWait is how long a console-mode call blocks for a SAME-TURN decision before returning
	// "pending — retry shortly" (DELEGENT_CONSENT_SYNC_WAIT, default 25s). Zero means the default.
	syncWait time.Duration
	// requestTTL is how long a persisted pending console request stays approvable — and the
	// in-memory console pendingConsent's ExpiresAt (DELEGENT_CONSENT_REQUEST_TTL, default 30m).
	// Zero means the default.
	requestTTL time.Duration
	// hub, when wired by the Registry, receives console park/resolve events for the SSE stream.
	// nil in stdio/dev mode and in unit tests — publishConsent is a no-op then.
	hub *ConsentHub

	// scopeTools maps each scope to the sorted, unique vendor tools it unlocks, computed ONCE
	// at construction by classifying every vendor tool. plan_access reads it to tell the agent
	// which tools a capability buys. nil in unit tests unless the harness builds it.
	scopeTools map[string][]string

	// toolDesc maps each vendor tool name to its human-facing description, captured ONCE at
	// construction from the mirrored upstream tool list. The consent render reads it to say
	// WHAT a call does ("List your repositories") instead of a bare scope label. Read-only
	// thereafter. nil in unit tests unless the harness builds it.
	toolDesc map[string]string

	// toolSem maps each vendor tool name to its derived, DISPLAY-ONLY semantic profile
	// (reversibility/open-world/…), computed ONCE at the mirror loop from each tool's
	// server-asserted annotations. The consent render reads it to append advisory risk markers.
	// NEVER consulted by any authorize/gate path. nil in unit tests unless the harness builds it.
	toolSem map[string]introspect.ToolSemantics

	// curatedSem is the operator-curated, DISPLAY-ONLY semantic overlay loaded from the adapter
	// doc's `semantics` section by loadConfig. At the mirror loop it takes precedence over the
	// live-annotation auto-derivation per tool (curated wins; auto is the fallback). Like toolSem,
	// NEVER consulted by any authorize/gate path.
	curatedSem map[string]introspect.ToolSemantics

	// logPayloads (DELEGENT_LOG_PAYLOADS, default ON) captures tool params + results on the
	// activity-log events. payloadMax (DELEGENT_LOG_PAYLOAD_MAX, default 8192) caps each captured
	// JSON payload — anything longer is replaced with a {"_truncated":N} marker. Both are read
	// ONCE at construction.
	logPayloads bool
	payloadMax  int
}

// Grant scope values for DELEGENT_GRANT_SCOPE.
const (
	grantScopeConnection = "connection" // the default: a grant lives and dies with its connection
	grantScopeUser       = "user"       // legacy: any connection resumes the principal's latest session
)

// grantScopeFromEnv reads DELEGENT_GRANT_SCOPE once (called at Gateway construction — never
// per request). Anything other than "user" means the connection-scoped default.
func grantScopeFromEnv() string {
	if os.Getenv("DELEGENT_GRANT_SCOPE") == grantScopeUser {
		return grantScopeUser
	}
	return grantScopeConnection
}

// GrantScopeName exposes the configured grant scope for the startup banner.
func GrantScopeName() string { return grantScopeFromEnv() }

// New builds a Gateway for target: loads its adapter/advisor/entitlements from the store,
// resolves the upstream credential via the SecretStore (warning and connecting WITHOUT it on
// failure), connects the upstream MCP session, and assembles the proxy server with the
// vendor's tools plus request_access/receipts (and, with DELEGENT_DELEGATION set, the
// delegation tools).
func New(ctx context.Context, st store.Store, sealer keyring.Sealer, target *store.Target) (*Gateway, error) {
	adapter, advisor, principals, curatedSem, err := loadConfig(ctx, st, target)
	if err != nil {
		return nil, err
	}

	// The operating principal is the target's OWNER (the user who created it). Agent keys let
	// a connection act as any authorized user; without one the gateway runs as the owner.
	rootName := target.Owner
	if rootName == "" {
		rootName = firstPrincipal(principals) // fall back to any entitled user
	}
	if rootName == "" {
		return nil, fmt.Errorf("target %q has no owner/entitlements — seed or create one first", target.ID)
	}

	g := &Gateway{
		targetID:         target.ID,
		adapter:          adapter,
		curatedSem:       curatedSem,
		st:               st,
		byConn:           map[string]string{},
		byConnCaps:       map[string]clientCaps{},
		byConnMeta:       map[string]callMeta{},
		byConnPolicy:     map[string][]string{},
		pending:          newPendingStore(nowMillis, func() string { return randHex(16) }),
		defaultPrincipal: rootName,
		grantScope:       grantScopeFromEnv(),
		flags:            featureFlagsFromEnv(),
		consoleConsent:   consoleConsentFromEnv(),
		syncWait:         consentSyncWaitFromEnv(),
		requestTTL:       consentRequestTTLFromEnv(),
		logPayloads:      logPayloadsFromEnv(),
		payloadMax:       logPayloadMaxFromEnv(),
	}

	rk := rootkeys.New(st, sealer)
	g.cp = controlplane.New(controlplane.Options{
		Vendor: target.ID, Adapter: adapter, Advisor: advisor, Principals: principals,
		RootName: rootName, RootKeys: rk, Store: st,
		Now: nowMillis, Rand: func() string { return randHex(8) },
	})
	g.br = broker.New(g.cp, st, sealer, nowMillis, func() string { return randHex(4) })

	// Resolve the upstream credential (if the target references one) via the SecretStore and
	// attach it to the upstream client — the agent never sees it.
	httpClient := &http.Client{}
	if target.CredentialRef != "" {
		secrets := secretstore.NewDB(st, sealer)
		switch target.CredentialKind {
		case "oauth2":
			// OAuth2 vendor: the sealed value at CredentialRef is a JSON TokenSet the
			// oauthSource refreshes and re-seals before injecting. Its client config
			// (endpoints, client_id, sealed client_secret) lives in the oauth_clients row.
			oc, err := st.GetOAuthClient(ctx, target.ID)
			if err != nil {
				log.Printf("⚠️ could not resolve credential %q: oauth client cfg missing: %v — connecting upstream WITHOUT it (re-register via POST /api/targets/{id}/oauth/register)", target.CredentialRef, err)
				break
			}
			// Only an EMPTY ClientSecretRef means a public client. A set ref that fails to
			// unseal is a real failure: skip building the source (mirroring the missing-cfg
			// posture above) rather than posting refreshes WITHOUT the client_secret.
			csec := ""
			if oc.ClientSecretRef != "" {
				v, err := secrets.Get(ctx, oc.ClientSecretRef)
				if err != nil {
					log.Printf("⚠️ could not resolve credential %q: client secret %q unavailable: %v — connecting upstream WITHOUT it (re-register via POST /api/targets/{id}/oauth/register)", target.CredentialRef, oc.ClientSecretRef, err)
					break
				}
				csec = v
			}
			src := newOAuthSource(oauthSourceCfg{
				ref:     target.CredentialRef,
				secrets: secrets,
				client:  oauth.RefreshInput{TokenEndpoint: oc.TokenEndpoint, ClientID: oc.ClientID, ClientSecret: csec, HTTP: http.DefaultClient},
			})
			httpClient.Transport = &authTransport{src: src, base: http.DefaultTransport}
		default: // "static_bearer", "" (default), and "query_param" (later task)
			if cred, err := secrets.Get(ctx, target.CredentialRef); err == nil && cred != "" {
				httpClient.Transport = &authTransport{src: staticSource{cred: cred}, base: http.DefaultTransport}
			} else if err != nil {
				log.Printf("⚠️ could not resolve credential %q: %v — connecting upstream WITHOUT it (re-add via PUT /api/targets/{id}/credential)", target.CredentialRef, err)
			}
		}
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "delegent", Version: "0.2.0"}, nil)
	g.upstream, err = client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: target.Endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect upstream %s: %w", target.Endpoint, err)
	}

	vendorTools, err := g.upstream.ListTools(ctx, nil)
	if err != nil {
		g.upstream.Close()
		return nil, fmt.Errorf("list upstream tools: %w", err)
	}

	// Invert the classifier: for each vendor tool, the scopes it needs → which tools each scope
	// unlocks. Built once so plan_access can show the agent the tools behind every capability.
	g.scopeTools = buildScopeTools(g.adapter, toolNames(vendorTools.Tools))

	// Declare the MCP Apps extension in our capabilities. Rendering is gated by the CLIENT's
	// declaration (checked per session below), but advertising ours is spec-clean and free.
	serverCaps := &mcp.ServerCapabilities{}
	serverCaps.AddExtension(uiExtensionKey, map[string]any{"mimeTypes": []string{consentWidgetMIME}})

	s := mcp.NewServer(&mcp.Implementation{Name: "delegent", Version: "0.2.0"}, &mcp.ServerOptions{
		Capabilities: serverCaps,
		Instructions: "Delegent is a consent gateway: every tool on this server reaches the real service only " +
			"within what the user has approved, and every decision is recorded.\n\n" +
			"Prefer Delegent's own tools first:\n" +
			"- plan_access lists the capabilities you can be granted; request_access then asks the human ONCE " +
			"for the bundle your task needs — do this up front instead of triggering a separate approval per " +
			"tool call. Access is additive: as the task grows, plan_access/request_access again.\n" +
			"- Fill _delegent_intent on EVERY call: one sentence, in the user's own words, on why this call " +
			"serves their task. The human approving reads it — clear intent gets faster approvals.\n" +
			"- A denial is the gateway working, not a bug. \"pending approval\": a human was asked — retry " +
			"shortly. \"not classified\" / \"cannot be granted\": no scope can allow it — tell the user, do NOT " +
			"retry or work around it. A vendor-outage note: your access is intact — just retry later.\n" +
			"- Sub-agents: narrow_access mints a strictly weaker session to hand down; escalate asks your " +
			"parent for more — neither grants by itself. receipts shows the audit trail; revoke drops held " +
			"access when the task is done.",
		// Log what each connecting client actually declares — the difference between a
		// consent dialog appearing and a fail-closed denial is whether the client (or the
		// bridge in front of it) advertises elicitation or the MCP Apps ui extension.
		InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
			ip := req.Session.InitializeParams()
			name, version, sampling := "unknown", "", false
			caps := clientCaps{}
			exts := []string{}
			if ip != nil {
				if ip.ClientInfo != nil {
					name, version = ip.ClientInfo.Name, ip.ClientInfo.Version
				}
				if ip.Capabilities != nil {
					caps.elicitation = ip.Capabilities.Elicitation != nil
					sampling = ip.Capabilities.Sampling != nil
					// Extensions are an alternate consent channel: a client that can't
					// elicit but declares the MCP Apps ui extension renders our consent
					// dialog as an in-chat widget instead.
					for k := range ip.Capabilities.Extensions {
						exts = append(exts, k)
					}
					_, caps.uiExt = ip.Capabilities.Extensions[uiExtensionKey]
					for k := range ip.Capabilities.Experimental {
						exts = append(exts, "experimental:"+k)
					}
					sort.Strings(exts)
				}
			}
			g.setCaps(req.Session.ID(), caps)
			// The agent key's consent-channel policy rides in on the verified TokenInfo; keep it
			// per connection so every later routing decision (which lacks the auth ctx) sees it.
			policy := channelPolicyFromContext(ctx)
			g.setPolicy(req.Session.ID(), policy)
			extList := "none"
			if len(exts) > 0 {
				extList = strings.Join(exts, ", ")
			}
			mode := caps.consentMode(g.consoleConsent, g.flags, policy)
			log.Printf("[delegent] client connected to %q: %s %s | elicitation=%v sampling=%v extensions=[%s] consent=%s%s",
				target.ID, name, version, caps.elicitation, sampling, extList, mode,
				map[bool]string{true: " (no consent channel ⇒ scope requests will be DENIED)"}[mode == consentDenied])

			// Activity log: one connection event per initialize, with the client identity.
			ev := g.eventBase(ctx, req.Session.ID())
			ev.Type = store.EventConnection
			ev.ClientName, ev.ClientVersion = name, version
			g.emit(ev)
		},
	})
	names := make([]string, 0, len(vendorTools.Tools))
	g.toolDesc = make(map[string]string, len(vendorTools.Tools))
	g.toolSem = make(map[string]introspect.ToolSemantics, len(vendorTools.Tools))
	for _, vt := range vendorTools.Tools {
		tool := &mcp.Tool{Name: vt.Name, Description: vt.Description, InputSchema: withIntentField(vt.InputSchema)}
		s.AddTool(tool, g.vendorTool(vt.Name))
		g.vendorToolInfos = append(g.vendorToolInfos, tool)
		names = append(names, vt.Name)
		g.toolDesc[vt.Name] = vt.Description
		// Curated (operator-stored) semantics win; live-annotation auto-derivation is the fallback
		// for any tool without a stored override. Display-only either way — never gates authority.
		if s, ok := g.curatedSem[vt.Name]; ok {
			g.toolSem[vt.Name] = s
		} else {
			g.toolSem[vt.Name] = introspect.DeriveSemantics(vt.Name, vt.Annotations)
		}
	}

	// open_access_dialog carries _meta.ui so MCP Apps hosts render its result as our in-chat
	// consent widget (request_access deliberately does NOT — see its registration below).
	// submit_consent_decision declares visibility ["app"], but that hiding
	// is HOST-enforced only — this server still answers tools/call for it from anyone, so
	// the declaration is cosmetic, not a security boundary. What the server itself enforces
	// (see widget.go): (a) the widget_token delivered solely in the open_access_dialog result's
	// _meta — content and structuredContent are model-visible and must never carry secrets;
	// (b) redemption bound to the opening connection and principal; (c) the single-use
	// 5-minute nonce.
	mcp.AddTool(s, &mcp.Tool{
		Name:        "plan_access",
		Description: "Plan your access up front. Returns the capabilities this server can grant you (minus what you already hold), each with a risk level and the tools it unlocks. Call this BEFORE using tools, then call request_access with the subset your task needs to get a single approval instead of one prompt per tool. You can call it again anytime you discover you need more.",
	}, g.handlePlanAccess)
	// request_access is the batch-consent tool for INLINE and CONSOLE clients — it carries NO
	// _meta.ui, so an MCP Apps host never renders a widget for it (that would double-consent a
	// client that also elicits, e.g. ChatGPT). Widget-only hosts are steered to open_access_dialog
	// on demand (see widgetConsentInstruction) — that tool carries the _meta.ui that renders the
	// in-chat dialog.
	mcp.AddTool(s, &mcp.Tool{
		Name:        "request_access",
		Description: "Request one or more capabilities (scopes) in a single approval dialog — use after plan_access to get everything your task needs at once. You can also call a tool directly and approve its access when prompted.",
	}, g.handleRequestAccess)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "open_access_dialog",
		Description: "Show the access-request dialog. FOR HOSTS THAT RENDER UI WIDGETS ONLY (e.g. Claude Desktop) — most clients should use request_access instead. Called when a consent-required message tells you to.",
		Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": consentWidgetURI}},
	}, g.handleOpenAccessDialog)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "submit_consent_decision",
		Description: "Submit the user's GRANT/DENY decision from the Delegent consent dialog. App-only: called by the consent widget, never by the model.",
		Meta:        mcp.Meta{"ui": map[string]any{"resourceUri": consentWidgetURI, "visibility": []string{"app"}}},
	}, g.handleSubmitConsent)
	s.AddResource(&mcp.Resource{
		URI:         consentWidgetURI,
		Name:        "delegent-consent",
		Title:       "Delegent consent dialog",
		Description: "The GRANT/DENY consent dialog MCP Apps-capable hosts render in-chat for request_access.",
		MIMEType:    consentWidgetMIME,
	}, serveConsentWidget)
	s.AddResource(&mcp.Resource{
		URI:         consentTokenURI,
		Name:        "delegent-consent-token",
		Description: "Widget-only token recovery for hosts that strip _meta from tool-result notifications.",
		MIMEType:    "application/json",
	}, g.serveConsentToken)
	mcp.AddTool(s, &mcp.Tool{Name: "receipts", Description: "Return the audit trail of every access decision Delegent has made (allows and denials, with reasons)."}, g.handleReceipts)
	mcp.AddTool(s, &mcp.Tool{Name: "revoke", Description: "Drop the access this connection currently holds — revokes your session's slips so the next tool call must re-consent. Pass {\"chain\": true} to also revoke any sub-agent sessions you minted."}, g.handleRevoke)
	if os.Getenv("DELEGENT_DELEGATION") != "" {
		mcp.AddTool(s, &mcp.Tool{Name: "narrow_access", Description: "Mint a strictly-weaker child session for a sub-agent (offline, no human)."}, g.handleNarrow)
		mcp.AddTool(s, &mcp.Tool{Name: "escalate", Description: "Ask for more than a session holds. Bubbles UP to the nearest ancestor that holds it and parks as pending — it does NOT grant."}, g.handleEscalate)
		mcp.AddTool(s, &mcp.Tool{Name: "approve_escalation", Description: "Approve an escalation addressed to a session you hold — a deliberate hand-down."}, g.handleApprove)
		mcp.AddTool(s, &mcp.Tool{Name: "pending_escalations", Description: "List escalation requests awaiting your approval."}, g.handlePending)
	}
	g.server = s

	storeKind := "durable"
	switch st.(type) {
	case *store.MemStore:
		storeKind = "in-memory"
	case *store.JSONFileStore:
		storeKind = "json-file"
	}
	log.Printf("[delegent] target %q → upstream %s | store: %s | tools: %s", target.ID, target.Endpoint, storeKind, strings.Join(names, ", "))
	if on := g.flags.active(); len(on) > 0 {
		log.Printf("⚙️  [delegent] feature flags ON for %q: %s — a capable client will fall through to the next consent channel", target.ID, strings.Join(on, ", "))
	}

	// Bare streamable handler: agent-key auth is enforced by the Registry BEFORE this gateway
	// is even built, so an unauthenticated request never triggers unsealing or a connect.
	g.handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
	if AuthRequired(st) {
		log.Printf("[delegent] MCP gateway for %q up (auth: agent key REQUIRED)", target.ID)
	} else {
		log.Printf("[delegent] MCP gateway for %q up (auth: OFF — dev)", target.ID)
	}

	return g, nil
}

// Handler is the HTTP surface of this gateway: the streamable MCP handler, wrapped in
// agent-key bearer auth when auth is on.
func (g *Gateway) Handler() http.Handler { return g.handler }

// Run serves the gateway's MCP server over the given transport (stdio dev mode).
func (g *Gateway) Run(ctx context.Context, t mcp.Transport) error { return g.server.Run(ctx, t) }

// Close tears down the upstream MCP session.
func (g *Gateway) Close() { g.upstream.Close() }

// AuthRequired gates the gateway on a valid agent key: on for every durable store, off for
// the in-memory dev store, and forceable off with DELEGENT_AUTH=off.
func AuthRequired(st store.Store) bool {
	if _, isMem := st.(*store.MemStore); isMem {
		return false
	}
	return os.Getenv("DELEGENT_AUTH") != "off"
}

// principalOf returns the authenticated user for this request (from the agent key), or the
// default (target owner) when auth is off.
func (g *Gateway) principalOf(ctx context.Context) string {
	if ti := auth.TokenInfoFromContext(ctx); ti != nil && ti.UserID != "" {
		return ti.UserID
	}
	return g.defaultPrincipal
}

func (g *Gateway) getSession(connID string) string {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	return g.byConn[connID]
}
func (g *Gateway) setSession(connID, h string) {
	g.sessMu.Lock()
	g.byConn[connID] = h
	g.sessMu.Unlock()
}
func (g *Gateway) clearSession(connID string) {
	g.sessMu.Lock()
	delete(g.byConn, connID)
	g.sessMu.Unlock()
}

// resumeSession returns the handle bound to this connection. In the default connection scope
// a connection only ever resumes the session handle it itself accumulated (byConn) — a grant
// earned in one conversation is never inherited by another. NOTE: because byConn is
// in-memory, a gateway rebuild (Registry.Invalidate) or an api restart drops it, so agents on
// existing connections re-consent in connection mode — accepted: re-asking the human beats
// silently resurrecting another conversation's authority. In user scope
// (DELEGENT_GRANT_SCOPE=user) a new connection falls back to the principal's latest live
// session from the store, as before. Returns "" if there is nothing to resume.
func (g *Gateway) resumeSession(connID string) string {
	if h := g.getSession(connID); h != "" {
		// A bound session that has EXPIRED or been REVOKED confers no authority — treat it as no
		// session so the next grant mints a FRESH one, instead of augmenting a dead session (which
		// would inherit its expired clock and grant nothing). Drop the stale binding.
		if !g.br.SessionLive(h) {
			g.clearSession(connID)
		} else {
			return h
		}
	}
	if g.grantScope != grantScopeUser {
		return ""
	}
	if h := g.br.LatestLiveSession(g.cp.RootName()); h != "" {
		g.setSession(connID, h)
		log.Printf("[delegent] resumed session %s (%s) for %s from store", h, g.br.AgentDisplayName(h), g.cp.RootName())
		return h
	}
	return ""
}

func text(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}
func toolError(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// toolResultText concatenates the text content of a result (used to surface a vendor-side error
// result — e.g. an upstream 503 — into the activity log). Capped so a huge body stays readable.
func toolResultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if b.Len() > 0 {
				b.WriteString(" ")
			}
			b.WriteString(tc.Text)
		}
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		s = "vendor returned an error result"
	}
	if len(s) > 500 {
		s = s[:500] + "…"
	}
	return s
}

// ---- consent legibility (action + risk + intent) ----

// callMeta is the human context a guarded vendor call carries into the consent render: WHAT the
// tool does (Tool/ToolDesc), WHERE (Target), WHY (Intent, the agent's self-declared purpose), and
// HOW risky (Effect). It is assembled at the gate and threaded into all three consent channels so
// the operator reads a legible sentence instead of a bare scope label.
type callMeta struct {
	Tool      string
	ToolDesc  string
	Target    string
	Intent    string
	Effect    core.Effect
	Semantics introspect.ToolSemantics // derived, DISPLAY-ONLY risk markers appended to the headline
}

// riskPhrase turns an effect mask into the operator-facing risk clause, picking the STRONGEST
// effect present (destructive/spend outrank write outranks read). An empty/unknown mask degrades
// to a neutral "changes state" rather than claiming a call is harmless.
func riskPhrase(e core.Effect) string {
	switch {
	case e&core.EffectDestructive != 0:
		return "⚠️ destructive — can delete or overwrite"
	case e&core.EffectSpends != 0:
		return "💸 spends money"
	case e&core.EffectWrite != 0:
		return "✍️ writes data"
	case e&core.EffectRead != 0:
		return "read-only"
	default:
		return "changes state"
	}
}

// semanticMarkers renders the DISPLAY-ONLY advisory risk clauses appended to the risk phrase —
// only affirmative values print (never "unknown"), reversible-then-openworld. Idempotency and cost
// are captured upstream but not surfaced in this cut. These markers are advisory: they never touch
// any authorize/gate path.
func semanticMarkers(s introspect.ToolSemantics) string {
	var out string
	if s.Reversible == "irreversible" {
		out += " · ⚠️ irreversible"
	}
	if s.OpenWorld == "yes" {
		out += " · 🌐 touches an external service"
	}
	return out
}

// humanizeTool renders a snake_case tool name as a readable action ("list_repos" → "list repos").
// It is the fallback when a vendor tool ships no description.
func humanizeTool(name string) string {
	return strings.ReplaceAll(name, "_", " ")
}

// consentHeadline is the single legible top line shown across ALL three consent channels, so they
// never drift: "<agent> wants to <action> on <target> — <risk>." plus a "Why:" line carrying the
// agent's declared intent (omitted entirely when no intent was declared — fail-soft). <action> is
// the tool's human description when present, else a humanized tool name.
func consentHeadline(agent string, m callMeta) string {
	who := agent
	if who == "" {
		who = "This agent"
	}
	action := m.ToolDesc
	if action == "" {
		action = humanizeTool(m.Tool)
	}
	// Verb clause: a specific tool reads "wants to <action>"; a batch/escalation ask with no single
	// tool degrades to "wants access".
	verb := "wants access"
	if action != "" {
		verb = "wants to " + action
	}
	line := who + " " + verb
	if m.Target != "" {
		line += " on " + m.Target
	}
	line += " — " + riskPhrase(m.Effect) + semanticMarkers(m.Semantics) + "."
	if m.Intent != "" {
		line += "\nWhy: \"" + m.Intent + "\""
	}
	return line
}

// ---- consent dialog (MCP elicitation) ----

type elicitConsent struct {
	ctx        context.Context
	ss         *mcp.ServerSession
	agent      string   // the requesting agent's chain identity ("new agent connection" pre-consent)
	connScoped bool     // connection grant scope: tell the human the grant stays with THIS conversation
	meta       callMeta // the WHAT/WHERE/WHY/HOW of this call, rendered as the legible headline
}

// consentUI builds the elicitation-backed Consent for a request, naming the agent whose
// session handle is asking (empty handle = a connection with no session yet). meta carries the
// call's action/target/intent/effect so the dialog leads with a legible headline, not a scope.
func (g *Gateway) consentUI(ctx context.Context, ss *mcp.ServerSession, handle string, meta callMeta) *elicitConsent {
	return &elicitConsent{ctx: ctx, ss: ss, agent: g.br.AgentDisplayName(handle), connScoped: g.grantScope == grantScopeConnection, meta: meta}
}

func (e *elicitConsent) Ask(r controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	props := map[string]any{}
	keyed := make([]string, len(r.Scopes))
	for i, sc := range r.Scopes {
		keyed[i] = sc.Scope
		title := sc.Scope + " — " + sc.Human
		if len(sc.Warnings) > 0 {
			title += " ⚠️ " + strings.Join(sc.Warnings, " ")
		}
		props["s"+strconv.Itoa(i)] = map[string]any{"type": "string", "enum": []string{"GRANT", "DENY"}, "default": "DENY", "title": title}
	}
	props["ttl"] = map[string]any{"type": "string", "enum": ttlLabels(), "default": ttlDefault().Label, "title": "How long?"}
	props["budget_usd"] = map[string]any{"type": "number", "default": 1, "title": "Budget (USD)"}

	// Lead with the legible headline (action + risk + intent); demote the scope string to a
	// footnote alongside the TTL/budget controls the human sets below.
	msg := consentHeadline(e.agent, e.meta)
	msg += "\n(scope: " + strings.Join(keyed, ", ") + " · choose TTL/budget below)"
	if e.connScoped {
		msg += "\nThis grant applies to THIS conversation/connection only, for the TTL you pick."
	}
	for _, w := range r.OverAskWarnings {
		msg += "\n" + w
	}
	if len(r.Ungrantable) > 0 {
		msg += "\n(not offered — Alice does not hold: " + strings.Join(r.Ungrantable, ", ") + ")"
	}
	res, err := e.ss.Elicit(e.ctx, &mcp.ElicitParams{Message: msg, RequestedSchema: map[string]any{"type": "object", "properties": props}})
	if err != nil {
		// The client cannot show a consent dialog. FAIL CLOSED: granting without a human in
		// the loop is a consent bypass — the exact failure this product exists to prevent.
		// DELEGENT_AUTOGRANT=1 restores the old auto-grant for curl/script testing ONLY.
		if os.Getenv("DELEGENT_AUTOGRANT") != "" {
			log.Printf("⚠️ elicitation unavailable (%v) — AUTO-GRANTING (DELEGENT_AUTOGRANT is set; never use in production)", err)
			return &controlplane.ConsentAnswer{Granted: append([]string{}, keyed...), TTLMinutes: ttlDefault().Minutes, BudgetUSD: 5}, nil
		}
		log.Printf("🔒 elicitation unavailable (%v) — DENYING: this client cannot show a consent dialog", err)
		return nil, nil
	}
	if res.Action != "accept" {
		return nil, nil
	}
	var granted []string
	for i, scope := range keyed {
		if res.Content["s"+strconv.Itoa(i)] == "GRANT" {
			granted = append(granted, scope)
		}
	}
	ttl := ttlDefault().Minutes
	if label, ok := res.Content["ttl"].(string); ok {
		ttl = ttlMinutesForLabel(label)
	}
	budget := 1.0
	if f, ok := res.Content["budget_usd"].(float64); ok {
		budget = f
	}
	return &controlplane.ConsentAnswer{Granted: granted, TTLMinutes: ttl, BudgetUSD: budget}, nil
}

// ---- per-call intent (_delegent_intent) ----

// intentField is the synthetic argument Delegent injects into every vendor tool's input schema so
// the agent self-declares WHY a call is needed. It is shown to the human at consent, recorded on
// the call, and stripped before the call is forwarded — the vendor never sees it.
const intentField = "_delegent_intent"

const intentFieldDesc = "One sentence, in the user's own terms, explaining WHY this call is needed for the current task. Shown to the human approving access. Not a restatement of the tool name."

// withIntentField returns a copy of a vendor tool's JSON Schema with the _delegent_intent string
// property added (never marked required — fail-soft). It shallow-clones the schema and its
// properties map so the upstream vendorTools structures are never mutated. A nil schema becomes a
// minimal object schema carrying just the intent property. Vendor tools come off the wire as
// map[string]any; any other shape is round-tripped through JSON so the injection still applies.
func withIntentField(schema any) any {
	prop := map[string]any{"type": "string", "description": intentFieldDesc}
	switch s := schema.(type) {
	case nil:
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{intentField: prop},
		}
	case map[string]any:
		out := make(map[string]any, len(s)+1)
		for k, v := range s {
			out[k] = v
		}
		if out["type"] == nil {
			out["type"] = "object"
		}
		props := map[string]any{}
		if existing, ok := out["properties"].(map[string]any); ok {
			for k, v := range existing {
				props[k] = v
			}
		}
		props[intentField] = prop
		out["properties"] = props
		return out
	default:
		b, err := json.Marshal(schema)
		if err != nil {
			return schema
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return schema
		}
		return withIntentField(m)
	}
}

// stripIntent pulls the declared intent out of a call's arguments and removes the key from the map
// that is forwarded upstream, so _delegent_intent NEVER reaches the vendor. A missing field yields
// "". The map is mutated in place (it is unmarshaled fresh per call) and returned for clarity.
func stripIntent(args map[string]any) (string, map[string]any) {
	if args == nil {
		return "", nil
	}
	intent, _ := args[intentField].(string)
	delete(args, intentField)
	return intent, args
}

// ---- the transparent vendor-tool proxy ----

// vendorTool wraps one upstream tool: authorize (requesting consent on demand), charge any
// spend against the budget, then forward.
func (g *Gateway) vendorTool(name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		if len(req.Params.Arguments) > 0 {
			_ = json.Unmarshal(req.Params.Arguments, &args)
		}
		// Pull the agent's self-declared intent and strip it so it never reaches the vendor. The
		// stripped args are what get classified, forwarded, and charged from here on.
		intent, args := stripIntent(args)
		body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}}
		amount := 0.0
		if v, ok := args["amount"].(float64); ok {
			amount = v
		}
		creq := core.Request{Action: "POST", Resource: "/mcp", Amount: amount, Body: body}
		c := core.Classify(g.adapter, creq)
		connID := req.Session.ID()
		handle := g.resumeSession(connID)

		// The legible consent context for this call — action/target/intent/effect — threaded into
		// whichever consent channel this connection uses.
		meta := callMeta{Tool: name, ToolDesc: g.toolDesc[name], Target: g.targetID, Intent: intent, Effect: c.Effect, Semantics: g.toolSem[name]}

		// Activity log: the tool call as it arrived (params captured per the payloads flag). Emitted
		// HERE, before the authorize/consent branch, so the declared intent is recorded on EVERY
		// vendor call — including one that sails through under a grant already held (no prompt).
		g.emit(g.toolCallEvent(ctx, connID, name, intent, req.Params.Arguments))

		// Authorize: forward straight through if the session already holds the scope, else open
		// the consent dialog for exactly the scopes this call needs.
		if handle == "" || func() bool { _, d, _ := g.br.Authorize(handle, creq); return !d.Allow }() {
			if c.Unknown {
				log.Printf("🔒 %s DENIED — unknown tool (fail closed)", name)
				errEv := g.eventBase(ctx, connID)
				errEv.Type = store.EventError
				errEv.Tool = name
				errEv.Reason = "unknown tool — not classified (fail closed)"
				g.emit(errEv)
				return toolError("🔒 DELEGENT: '" + name + "' is not classified — denied (fail closed). No scope can grant it."), nil
			}

			// A vendor call that needs consent: record the ask before routing to a channel.
			reqEv := g.eventBase(ctx, connID)
			reqEv.Type = store.EventPermissionRequested
			reqEv.Tool = name
			reqEv.Scopes = c.Scopes
			reqEv.Reason = "tool: " + name
			g.emit(reqEv)
			// DELEGENT_AUTOGRANT (scripts/tests) is the highest-priority override: it bypasses
			// mode routing entirely and takes the elicitation path below, which auto-answers
			// when the client cannot show a dialog. Otherwise route by the client's channel:
			// widget-capable clients get the two-phase widget flow; clients with NEITHER
			// elicitation nor the widget (e.g. ChatGPT) get the console channel — park and BLOCK
			// until a human GRANTs in the web console. The vendor tool is NOT executed on either
			// non-elicit path; the model retries after a grant.
			if os.Getenv("DELEGENT_AUTOGRANT") == "" {
				switch g.consentModeFor(connID) {
				case consentWidget:
					return g.widgetConsentInstruction(ctx, connID, name, c.Scopes, meta), nil
				case consentConsole:
					return g.consoleConsentBlock(ctx, connID, name, c.Scopes, meta), nil
				}
			}
			nh, msg, granted := g.br.Grant(g.principalOf(ctx), handle, c.Scopes, "tool: "+name, g.consentUI(ctx, req.Session, handle, meta))
			if !granted {
				log.Printf("🔒 %s DENIED — %s", name, msg)
				denyEv := g.eventBase(ctx, connID)
				denyEv.Type = store.EventPermissionDenied
				denyEv.Tool = name
				denyEv.Scopes = c.Scopes
				denyEv.Reason = msg
				g.emit(denyEv)
				return toolError("🔒 DELEGENT: '" + name + "' needs " + strings.Join(c.Scopes, ", ") + " — not granted. " + msg), nil
			}
			if handle == "" {
				g.setSession(connID, nh)
				handle = nh
				log.Printf("[delegent] session %s (%s) minted for connection %s", nh, g.br.AgentDisplayName(nh), connID)
			}
			grantEv := g.eventBase(ctx, connID)
			grantEv.Type = store.EventPermissionGranted
			grantEv.Tool = name
			grantEv.Scopes = g.br.LiveScopes(handle)
			grantEv.Reason = "tool: " + name
			g.emit(grantEv)
			if _, d, _ := g.br.Authorize(handle, creq); !d.Allow {
				return toolError("🔒 DELEGENT: '" + name + "' denied — " + d.Reason), nil
			}
		}

		// Spending calls are charged atomically against the session budget — the ceiling the
		// human set in the consent dialog, enforced so it cannot be raced past.
		if c.Effect&core.EffectSpends != 0 {
			if ok, msg := g.br.Charge(handle, amount, name); !ok {
				log.Printf("🔒 %s DENIED — %s", name, msg)
				return toolError("🔒 DELEGENT: '" + name + "' refused — " + msg), nil
			}
		}

		log.Printf("✅ %s ALLOWED (%s)", name, core.EffectNames(c.Effect))
		return g.forward(ctx, connID, name, args)
	}
}

// forward calls the upstream vendor tool and returns its own result transparently. It is also
// the single choke point for the tool_response activity-log event: a real upstream transport
// failure logs one `error` event; any answered call (even a vendor-side IsError result) logs one
// `tool_response`, so a failure is never double-logged.
func (g *Gateway) forward(ctx context.Context, connID, name string, args map[string]any) (*mcp.CallToolResult, error) {
	res, err := g.upstream.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	base := g.eventBase(ctx, connID)
	base.Tool = name
	if err != nil {
		base.Type = store.EventError
		base.Error = err.Error()
		g.emit(base)
		// A transport failure that looks like a vendor outage (5xx/connectivity/rate limit) is
		// NOT a permissions problem — annotate it so the agent narrates the outage and retries
		// rather than telling the user to reconnect with more scopes.
		if looksTransient(err.Error()) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{
				&mcp.TextContent{Text: "upstream error: " + err.Error()},
				&mcp.TextContent{Text: transientTransportNote},
			}}, nil
		}
		return toolError("upstream error: " + err.Error()), nil
	}
	base.Type = store.EventToolResponse
	base.Result = g.capValue(res)
	// A transport-level success can still carry a vendor-side ERROR result (e.g. GitHub returns
	// a 503 as an IsError tool result). Surface it on the event so the activity log shows the
	// failure instead of a silent-looking response.
	if res != nil && res.IsError {
		base.Error = toolResultText(res)
	}
	g.emit(base)
	// Annotate (after the event capture, so the log holds the vendor's raw error) a vendor-side
	// error that looks transient/5xx — a genuine 4xx auth/validation error passes through
	// unannotated so the agent can act on it.
	return annotateTransient(res), nil
}

// transientSignals are the case-insensitive substrings that mark an upstream/vendor error as a
// transient/5xx/outage condition rather than a permissions or validation failure.
var transientSignals = []string{
	"503", "502", "500", "504", "429",
	"service unavailable", "temporarily unavailable", "rate limit",
	"upstream", "bad gateway", "gateway timeout", "try again",
}

// looksTransient reports whether s carries a transient/5xx/upstream signal (case-insensitive).
func looksTransient(s string) bool {
	l := strings.ToLower(s)
	for _, sig := range transientSignals {
		if strings.Contains(l, sig) {
			return true
		}
	}
	return false
}

const (
	// transientNote annotates a vendor-side IsError result that looks like a 5xx/outage.
	transientNote = "⚠️ Delegent: the upstream vendor returned a transient/5xx error. This is a VENDOR-SIDE OUTAGE, not a permissions problem — your access is intact. Retry shortly; do NOT reconnect or request additional access."
	// transientTransportNote annotates a transport-level failure reaching the vendor.
	transientTransportNote = "⚠️ Delegent: could not reach the upstream vendor (connectivity/outage) — NOT a permissions problem; your access is intact. Retry shortly; do NOT reconnect or request additional access."
)

// annotateTransient appends the Delegent outage note to a vendor-side error result whose text
// looks transient/5xx, leaving the vendor's own content intact (stay transparent). It returns res
// unchanged when res is nil, is not an error, or is a genuine non-transient error (e.g. a 4xx
// auth/validation failure the agent should act on). Pure — unit-testable without a live upstream.
func annotateTransient(res *mcp.CallToolResult) *mcp.CallToolResult {
	if res == nil || !res.IsError {
		return res
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
			b.WriteString(" ")
		}
	}
	if !looksTransient(b.String()) {
		return res
	}
	res.Content = append(res.Content, &mcp.TextContent{Text: transientNote})
	return res
}

// ---- management tools (authority, delegation, audit) ----

type requestAccessArgs struct {
	Scopes []string `json:"scopes" jsonschema:"scopes to pre-grant, e.g. [\"files:read\",\"files:write\"]"`
	Reason string   `json:"reason" jsonschema:"why the task needs this access"`
}
type narrowArgs struct {
	Session string   `json:"session" jsonschema:"the session to narrow"`
	Effects []string `json:"effects,omitempty" jsonschema:"the effect SET the child may have, e.g. [\"read\"]"`
	Scopes  []string `json:"scopes,omitempty" jsonschema:"the scopes the child may have"`
	Ceiling []string `json:"ceiling,omitempty" jsonschema:"scopes the child may pull LATER without asking you"`
	Budget  *float64 `json:"budget,omitempty"`
	Minutes *int     `json:"minutes,omitempty"`
}
type escalateArgs struct {
	Session string   `json:"session" jsonschema:"the session that is short on authority"`
	Scopes  []string `json:"scopes" jsonschema:"the additional scopes needed"`
	Reason  string   `json:"reason" jsonschema:"why the task needs them"`
}
type approveArgs struct {
	Session string `json:"session" jsonschema:"the ancestor session that was asked"`
	ID      string `json:"id" jsonschema:"the escalation id, e.g. esc_1a2b3c4d"`
}
type sessionArg struct {
	Session string `json:"session"`
}

// consentModeFor is the consent channel for a connection — the routing decision, factored out
// so the entry-tool handlers below (and their tests) can consult it without a live req.Session.
func (g *Gateway) consentModeFor(connID string) consentMode {
	return g.capsOf(connID).consentMode(g.consoleConsent, g.flags, g.policyOf(connID))
}

// reqAccessWidgetRedirect is the NON-error result request_access returns to a widget-mode client:
// request_access has no _meta.ui, so it can never render the dialog — bounce the model to
// open_access_dialog (which does). Returns nil for non-widget clients (proceed normally).
func (g *Gateway) reqAccessWidgetRedirect(connID string) *mcp.CallToolResult {
	if g.consentModeFor(connID) == consentWidget {
		return text("This host renders access requests as an in-chat dialog — call open_access_dialog with {\"scopes\":[...],\"reason\":...} instead.")
	}
	return nil
}

// openDialogNonWidgetRedirect is the NON-error result open_access_dialog returns to a client that
// does NOT render widgets: without _meta.ui a structuredContent-only dialog is useless, so bounce
// it to request_access. Returns nil for widget clients (proceed to the widget flow).
func (g *Gateway) openDialogNonWidgetRedirect(connID string) *mcp.CallToolResult {
	if g.consentModeFor(connID) != consentWidget {
		return text("Your client doesn't render widgets — call request_access with these scopes instead.")
	}
	return nil
}

func (g *Gateway) handleRequestAccess(ctx context.Context, req *mcp.CallToolRequest, a requestAccessArgs) (*mcp.CallToolResult, any, error) {
	connID := req.Session.ID()
	// DELEGENT_AUTOGRANT bypasses mode routing (elicitation path auto-answers). Otherwise:
	// widget-capable clients are redirected to open_access_dialog (request_access has no
	// _meta.ui and cannot render the dialog); clients with neither elicitation nor the widget
	// block on a human GRANT in the web console.
	if os.Getenv("DELEGENT_AUTOGRANT") == "" {
		if r := g.reqAccessWidgetRedirect(connID); r != nil {
			log.Printf("request_access — widget-mode client redirected to open_access_dialog")
			return r, nil, nil
		}
	}
	// Activity log: the access ask itself (the grant/deny is logged where it is decided — the
	// elicitation path below, or mintPending for the console channel).
	reqEv := g.eventBase(ctx, connID)
	reqEv.Type = store.EventPermissionRequested
	reqEv.Scopes = a.Scopes
	reqEv.Reason = a.Reason
	g.emit(reqEv)
	if os.Getenv("DELEGENT_AUTOGRANT") == "" {
		switch g.consentModeFor(connID) {
		case consentConsole:
			reason := a.Reason
			if reason == "" {
				reason = "request_access"
			}
			return g.consoleRequestAccess(ctx, connID, reason, a.Scopes), nil, nil
		}
	}
	h := g.resumeSession(connID)
	nh, msg, granted := g.br.Grant(g.principalOf(ctx), h, a.Scopes, a.Reason, g.consentUI(ctx, req.Session, h, callMeta{Target: g.targetID, Intent: a.Reason}))
	if granted && h == "" {
		g.setSession(connID, nh)
		log.Printf("[delegent] session %s (%s) minted for connection %s", nh, g.br.AgentDisplayName(nh), connID)
	}
	decEv := g.eventBase(ctx, connID)
	decEv.Reason = msg
	if granted {
		decEv.Type = store.EventPermissionGranted
		decEv.Scopes = g.br.LiveScopes(g.resumeSession(connID))
	} else {
		decEv.Type = store.EventPermissionDenied
		decEv.Scopes = a.Scopes
	}
	g.emit(decEv)
	log.Printf("request_access — granted=%v %s", granted, msg)
	return text(msg), nil, nil
}

// handleOpenAccessDialog is the WIDGET entry tool: it carries _meta.ui.resourceUri so an MCP Apps
// host renders our in-chat consent dialog. Widget-only clients are steered here on demand by the
// consent-required message. A non-widget client that reaches it by mistake is bounced back to
// request_access (a structuredContent-only dialog with no _meta.ui is useless to it). On a
// widget-mode client it runs the SAME two-phase flow request_access used to — widgetRequestAccess.
func (g *Gateway) handleOpenAccessDialog(ctx context.Context, req *mcp.CallToolRequest, a requestAccessArgs) (*mcp.CallToolResult, any, error) {
	connID := req.Session.ID()
	if r := g.openDialogNonWidgetRedirect(connID); r != nil {
		log.Printf("open_access_dialog — non-widget client redirected to request_access")
		return r, nil, nil
	}
	// Activity log: the access ask itself (the grant/deny is logged at mintPending).
	reqEv := g.eventBase(ctx, connID)
	reqEv.Type = store.EventPermissionRequested
	reqEv.Scopes = a.Scopes
	reqEv.Reason = a.Reason
	g.emit(reqEv)
	return g.widgetRequestAccess(ctx, req, a)
}

// ---- capability discovery (plan_access) ----

type planAccessArgs struct {
	Task string `json:"task,omitempty" jsonschema:"what you are trying to do (optional, for your own planning)"`
}

// planScope is one grantable capability in the plan_access result: everything the human's
// dialog would show for it, plus the vendor tools it unlocks. No secrets — this is model-visible.
type planScope struct {
	Scope    string   `json:"scope"`
	Human    string   `json:"human"`
	Risk     string   `json:"risk"`
	Warnings []string `json:"warnings,omitempty"`
	Tools    []string `json:"tools,omitempty"`
}

// planAccessResult is the machine (structuredContent) view of a capability plan: what the
// session already holds, what remains grantable, and how to ask for it.
type planAccessResult struct {
	Held      []string    `json:"held"`
	Available []planScope `json:"available"`
	Guidance  string      `json:"guidance"`
}

// handlePlanAccess is capability discovery: it returns the scopes this session can still be
// granted (the principal's entitlements minus what the session already holds), each annotated
// with its risk and the tools it unlocks, so the agent can batch-request via request_access and
// take ONE approval instead of one prompt per tool. It grants nothing and asks no human.
func (g *Gateway) handlePlanAccess(ctx context.Context, req *mcp.CallToolRequest, _ planAccessArgs) (*mcp.CallToolResult, any, error) {
	result := g.planAccess(g.principalOf(ctx), req.Session.ID())
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: planAccessText(result.Held, result.Available, result.Guidance)}}}, result, nil
}

// planAccess computes the capability plan for a principal on a given connection: the scopes the
// session already holds, and the grantable-but-not-yet-held remainder with risk/tools. Pure
// query — grants nothing, asks no human. Extracted from the handler so it is testable headless.
func (g *Gateway) planAccess(principal, connID string) planAccessResult {
	held := g.heldScopes(connID)
	heldSet := map[string]bool{}
	for _, s := range held {
		heldSet[s] = true
	}

	cr := g.cp.DescribeConsent(principal, g.cp.AllScopes(), "")
	available := make([]planScope, 0, len(cr.Scopes))
	for _, sc := range cr.Scopes {
		if heldSet[sc.Scope] {
			continue // already held — plan_access shows only what REMAINS grantable
		}
		available = append(available, planScope{
			Scope: sc.Scope, Human: sc.Human, Risk: sc.Risk, Warnings: sc.Warnings,
			Tools: g.scopeTools[sc.Scope],
		})
	}
	return planAccessResult{Held: held, Available: available, Guidance: planGuidance(held, available)}
}

// planGuidance is the human/agent-facing steer returned with a plan: how to batch-request and
// the additive-access promise. It names no scope value and carries nothing secret.
func planGuidance(held []string, available []planScope) string {
	if len(available) == 0 {
		if len(held) > 0 {
			return "You already hold everything this server offers you. Access is additive — if the task later needs more, call plan_access/request_access again."
		}
		return "There is nothing this server can grant you here — the principal is entitled to no capabilities on this target."
	}
	return "Pick the capabilities your task needs and request them TOGETHER via request_access to get a SINGLE approval dialog instead of one prompt per tool. Nothing above is secret. Access is additive: call plan_access/request_access again anytime the task grows and needs more — new grants stack onto what you already hold."
}

// planAccessText renders the concise human-readable summary the model reads (structuredContent
// is the machine view). It lists held scopes and each available capability with its risk/tools.
func planAccessText(held []string, available []planScope, guidance string) string {
	var b strings.Builder
	if len(held) > 0 {
		b.WriteString("Already held: " + strings.Join(held, ", ") + "\n")
	} else {
		b.WriteString("Already held: (none)\n")
	}
	if len(available) == 0 {
		b.WriteString("Available to request: (none)\n")
	} else {
		b.WriteString("Available to request:\n")
		for _, s := range available {
			line := "  - " + s.Scope
			if s.Risk != "" {
				line += " [" + s.Risk + "]"
			}
			if s.Human != "" {
				line += " — " + s.Human
			}
			if len(s.Tools) > 0 {
				line += " (tools: " + strings.Join(s.Tools, ", ") + ")"
			}
			b.WriteString(line + "\n")
			for _, w := range s.Warnings {
				b.WriteString("      " + w + "\n")
			}
		}
	}
	b.WriteString(guidance)
	return b.String()
}

// heldScopes returns the scopes this connection's session currently holds, or nil if it has no
// live session. It reuses the broker's liveness notion (LiveScopes): a revoked or expired
// session confers nothing, so its scopes are not counted as held.
func (g *Gateway) heldScopes(connID string) []string {
	return g.br.LiveScopes(g.resumeSession(connID))
}

func (g *Gateway) handleNarrow(ctx context.Context, _ *mcp.CallToolRequest, a narrowArgs) (*mcp.CallToolResult, any, error) {
	_, msg, ok := g.br.Narrow(a.Session, broker.NarrowOpts{Effects: a.Effects, Scopes: a.Scopes, Ceiling: a.Ceiling, Budget: a.Budget, Minutes: a.Minutes})
	log.Printf("narrow_access — ok=%v %s", ok, msg)
	return text(msg), nil, nil
}
func (g *Gateway) handleEscalate(ctx context.Context, req *mcp.CallToolRequest, a escalateArgs) (*mcp.CallToolResult, any, error) {
	msg, granted := g.br.Escalate(a.Session, a.Scopes, a.Reason, g.consentUI(ctx, req.Session, a.Session, callMeta{Target: g.targetID, Intent: a.Reason}))
	log.Printf("escalate — granted=%v %s", granted, msg)
	return text(msg), nil, nil
}
func (g *Gateway) handleApprove(ctx context.Context, req *mcp.CallToolRequest, a approveArgs) (*mcp.CallToolResult, any, error) {
	// Approval is a deliberate hand-down by the PARENT: the calling connection must itself
	// be bound to the approving session. Handle possession alone is not enough — the child
	// knows escalation ids, and must never be able to approve its own request.
	if bound := g.getSession(req.Session.ID()); bound != a.Session {
		log.Printf("approve_escalation REJECTED — connection is bound to %q, not the approving session %q", bound, a.Session)
		return toolError("approve_escalation must be called from the connection that holds the approving session"), nil, nil
	}
	msg, ok := g.br.ApproveEscalation(a.Session, a.ID)
	log.Printf("approve_escalation — ok=%v %s", ok, msg)
	return text(msg), nil, nil
}
func (g *Gateway) handlePending(ctx context.Context, _ *mcp.CallToolRequest, a sessionArg) (*mcp.CallToolResult, any, error) {
	b, _ := json.MarshalIndent(g.br.PendingEscalations(a.Session), "", "  ")
	return text(string(b)), nil, nil
}
func (g *Gateway) handleReceipts(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	// Backward-compatible: still return the receipts array under "receipts", and ADD a per-principal
	// tamper-evidence verdict under "chain" so the agent/operator can see the log is intact.
	out := struct {
		Receipts []store.Receipt          `json:"receipts"`
		Chain    controlplane.ChainStatus `json:"chain"`
	}{
		Receipts: g.cp.Receipts(),
		Chain:    g.cp.VerifyReceiptsFor(g.principalOf(ctx)),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return text(string(b)), nil, nil
}

type revokeArgs struct {
	Chain bool `json:"chain,omitempty" jsonschema:"also revoke sub-agent sessions this connection minted"`
}

// handleRevoke drops the CALLING connection's own authority: it revokes the session bound to
// this connection (and, with chain, its descendants) and clears the connection→session map so
// the next tool call re-consents. Self-service only — a connection can revoke nothing but what
// it holds, so this is safe to expose without a human.
func (g *Gateway) handleRevoke(ctx context.Context, req *mcp.CallToolRequest, a revokeArgs) (*mcp.CallToolResult, any, error) {
	connID := req.Session.ID()
	handle := g.getSession(connID)
	if handle == "" {
		return text("Nothing to revoke — this connection holds no active grant."), nil, nil
	}
	n := g.br.RevokeSelf(handle, a.Chain)
	g.clearSession(connID)
	log.Printf("🗝️ revoke — connection dropped %s (%d session(s), chain=%v)", handle, n, a.Chain)
	if n == 0 {
		return text("Access already revoked. The next tool call will ask for consent again."), nil, nil
	}
	return text(fmt.Sprintf("Revoked %d session(s). Access dropped — the next tool call will ask for consent again.", n)), nil, nil
}

// makeVerifier resolves a presented Bearer token to its user: hash → agent key → user, rejecting
// unknown/revoked keys and users not entitled on THIS target. It sets UserID (which the SDK also
// binds the session to, preventing hijack) and touches last-used.
func makeVerifier(st store.Store, targetID string) auth.TokenVerifier {
	return func(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
		// The client always sees the same bare 401; the log gets the distinct reason.
		k, err := st.GetAgentKeyByHash(ctx, agentkey.Hash(token))
		if err != nil {
			log.Printf("[delegent] token rejected: unknown key: %v", err)
			return nil, auth.ErrInvalidToken
		}
		if k.RevokedAt != 0 {
			log.Printf("[delegent] token rejected: key %s revoked", k.ID)
			return nil, auth.ErrInvalidToken
		}
		ent, err := st.GetEntitlement(ctx, k.UserID, targetID)
		if err != nil {
			log.Printf("[delegent] token rejected: user %s not entitled on target %s", k.UserID, targetID)
			return nil, auth.ErrInvalidToken // valid key, but no access to this target
		}
		go func() { _ = st.TouchAgentKey(context.Background(), k.ID, nowMillis()) }()
		return &auth.TokenInfo{
			UserID:     k.UserID,
			Scopes:     ent.Effective(),               // scopes minus the operator's toggle-offs
			Expiration: time.Now().AddDate(100, 0, 0), // agent keys don't expire; they're revoked
			// Extra threads the caller's durable identity (key prefix/name) and resolved IP to the
			// activity log; key_name survives rotation, so it is the aggregation key there.
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

// loadConfig reads the fronted vendor's configuration from the store: the target's adapter
// and advisor documents (parsed with the same code that read them off disk), and its
// principals' entitlements.
func loadConfig(ctx context.Context, st store.Store, target *store.Target) (core.Adapter, loader.Advisor, map[string][]string, map[string]introspect.ToolSemantics, error) {
	var coreAdapter core.Adapter
	var advisor loader.Advisor

	ad, err := st.GetAdapter(ctx, target.AdapterID)
	if err != nil {
		return coreAdapter, advisor, nil, nil, fmt.Errorf("load adapter %q: %w", target.AdapterID, err)
	}
	if err := json.Unmarshal(ad.Doc, &coreAdapter); err != nil {
		return coreAdapter, advisor, nil, nil, fmt.Errorf("parse adapter %q: %w", target.AdapterID, err)
	}
	// Extract the DISPLAY-ONLY curated semantics that ride inside the adapter doc as a sibling of
	// `classify`. Parsed separately (NOT through core.Adapter) so enforcement is untouched — a bad
	// or absent `semantics` key leaves the map nil and never fails the load.
	var semDoc struct {
		Semantics map[string]introspect.ToolSemantics `json:"semantics"`
	}
	_ = json.Unmarshal(ad.Doc, &semDoc)
	curatedSem := semDoc.Semantics
	if target.AdvisorID != "" {
		av, err := st.GetAdvisor(ctx, target.AdvisorID)
		if err != nil {
			return coreAdapter, advisor, nil, nil, fmt.Errorf("load advisor %q: %w", target.AdvisorID, err)
		}
		if err := json.Unmarshal(av.Doc, &advisor); err != nil {
			return coreAdapter, advisor, nil, nil, fmt.Errorf("parse advisor %q: %w", target.AdvisorID, err)
		}
	}
	// entitlements for every user on this target → principal-id → scopes map, used by the
	// control plane's entitlement ceiling.
	ents, err := st.ListEntitlementsForTarget(ctx, target.ID)
	if err != nil {
		return coreAdapter, advisor, nil, nil, fmt.Errorf("load entitlements for %q: %w", target.ID, err)
	}
	m := map[string][]string{}
	for _, e := range ents {
		m[e.UserID] = e.Effective() // scopes minus the operator's toggle-offs
	}
	return coreAdapter, advisor, m, curatedSem, nil
}

// authTransport injects the resolved upstream credential as a Bearer header. The agent never
// sees it — Delegent attaches it on the way out.
type authTransport struct {
	src  CredentialSource
	base http.RoundTripper
}

func (a *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := a.src.Bearer(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return a.base.RoundTrip(r)
}

// firstPrincipal returns the lexicographically first principal id (deterministic pick of the
// operating principal when a target has one or more).
func firstPrincipal(principals map[string][]string) string {
	first := ""
	for id := range principals {
		if first == "" || id < first {
			first = id
		}
	}
	return first
}

// toolNames extracts the names of the upstream vendor tools.
func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

// buildScopeTools inverts the classifier into scope → sorted-unique tool names: it classifies a
// tools/call for each vendor tool (mirroring vendorTool's request shape) and, for every scope
// that call requires, records the tool under it. Tools that classify as unknown contribute
// nothing. Called once at construction — the result is read-only thereafter.
func buildScopeTools(adapter core.Adapter, names []string) map[string][]string {
	seen := map[string]map[string]bool{}
	for _, name := range names {
		body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": map[string]any{}}}
		c := core.Classify(adapter, core.Request{Action: "POST", Resource: "/mcp", Body: body})
		if c.Unknown {
			continue
		}
		for _, s := range c.Scopes {
			if seen[s] == nil {
				seen[s] = map[string]bool{}
			}
			seen[s][name] = true
		}
	}
	out := make(map[string][]string, len(seen))
	for s, set := range seen {
		tools := make([]string, 0, len(set))
		for t := range set {
			tools = append(tools, t)
		}
		sort.Strings(tools)
		out[s] = tools
	}
	return out
}

func nowMillis() int64 { return time.Now().UnixMilli() }
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
