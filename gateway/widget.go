// MCP Apps consent widget (extension io.modelcontextprotocol/ui, spec 2026-01-26): clients
// that cannot elicit but declare the ui extension (Claude Desktop) get the consent dialog as
// an in-chat widget instead of a fail-closed denial. Two-phase flow:
//
//  1. a guarded vendor call (or open_access_dialog) mints a pending consent nonce and — via
//     open_access_dialog, whose tool _meta.ui.resourceUri points at ui://delegent/consent —
//     returns the ask as structuredContent, which the host streams into the sandboxed widget
//     (ui/notifications/tool-result), together with a widget_token carried ONLY in the
//     result's _meta;
//  2. the widget posts the human's decision back through submit_consent_decision; the gateway
//     redeems the single-use nonce and mints through the SAME broker path inline elicitation
//     uses.
//
// Trust boundary — read this before touching the flow. submit_consent_decision declares
// visibility ["app"], but that hiding is enforced by the HOST alone: this server answers
// tools/call for it from anything on the wire, model included. The guarantees the server
// itself enforces are what actually gate a grant:
//
//	(a) the widget_token, delivered solely in the open_access_dialog result's _meta — the
//	    widget-only channel. content and structuredContent are MODEL-VISIBLE and must never
//	    carry secrets;
//	(b) redemption is bound to the connection and principal that opened the request;
//	(c) the request_id is a single-use, 5-minute nonce.
//
// The widget click is UI, not proof: only the server-side redemption grants anything.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/controlplane"
	"delegent.dev/gateway/store"
)

const (
	// uiExtensionKey is the MCP Apps extension identifier a client declares in
	// initialize capabilities.extensions when it can render ui:// widgets.
	uiExtensionKey = "io.modelcontextprotocol/ui"
	// consentWidgetURI is the ui:// resource holding the consent dialog template.
	consentWidgetURI = "ui://delegent/consent"
	// consentWidgetMIME is the MIME type the 2026-01-26 Apps spec REQUIRES for app HTML.
	consentWidgetMIME = "text/html;profile=mcp-app"
	// consentTokenURI is the widget's token-recovery resource for hosts that strip _meta
	// from tool-result notifications (Claude Desktop): the widget fetches it via the bridge's
	// resources/read — a channel the model cannot invoke on those hosts. The handler answers
	// only with the CALLING connection's own latest pending request.
	consentTokenURI = "ui://delegent/consent-token"
	// consentDecisionWait is how long a widget-mode request_access call blocks for the
	// human's decision before falling back to the two-phase "dialog shown, wait" answer.
	// Kept under typical 60s host/proxy request ceilings (cmd/api itself sets no
	// WriteTimeout, so the server never cuts the response off).
	consentDecisionWait = 50 * time.Second
)

// consentMode is how a given client session can obtain human consent.
type consentMode string

const (
	consentInline  consentMode = "inline"  // MCP elicitation: the current dialog flow
	consentWidget  consentMode = "widget"  // MCP Apps: render our ui:// consent widget
	consentConsole consentMode = "console" // neither channel, but a human can GRANT in the web console
	consentDenied  consentMode = "denied"  // no channel at all: fail closed (DELEGENT_AUTOGRANT aside)
)

// clientCaps is what a connected client declared at initialize, kept per session so every
// consent decision routes to a channel that session can actually render.
type clientCaps struct {
	elicitation bool
	uiExt       bool
}

// featureFlags are test toggles (FF_* env, read once at construction) that FORCE-DISABLE a
// consent channel so a capable client falls through to the next — letting you exercise the
// widget or console path on a client (Claude Code, ChatGPT) that would otherwise use
// elicitation. They never make consent EASIER: a disabled channel routes to the next real
// channel or fails closed; they cannot auto-grant.
type featureFlags struct {
	bypassElicitation bool // FF_BYPASS_ELICITATION: ignore a client's elicitation capability
	bypassWidget      bool // FF_BYPASS_WIDGETS: ignore a client's MCP Apps ui capability
}

func envTrue(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func featureFlagsFromEnv() featureFlags {
	return featureFlags{
		bypassElicitation: envTrue("FF_BYPASS_ELICITATION"),
		bypassWidget:      envTrue("FF_BYPASS_WIDGETS"),
	}
}

func (f featureFlags) active() []string {
	var on []string
	if f.bypassElicitation {
		on = append(on, "FF_BYPASS_ELICITATION")
	}
	if f.bypassWidget {
		on = append(on, "FF_BYPASS_WIDGETS")
	}
	return on
}

// consentMode picks the consent channel for a session. With no key policy (empty), precedence
// is capability order: inline elicitation, then the MCP Apps widget, then — when the client can
// do NEITHER — the web console (a human GRANTs the parked request in the browser), unless
// console consent is disabled, in which case there is no channel and the request fails closed.
// Feature flags can force-disable a channel so a capable client falls through.
//
// An explicit per-key policy (agent_keys.consent_channels) replaces both the capability order
// AND the env feature flags: the first listed channel the client actually supports wins, and
// the console is ALWAYS the final fallback after the list — a policy chooses the channel but
// can never remove human approval. Unknown channel names (e.g. a future "slack" on an older
// build) are skipped. DELEGENT_AUTOGRANT is a higher-priority override still, handled in
// vendorTool, so it is not represented here.
func (c clientCaps) consentMode(consoleEnabled bool, ff featureFlags, policy []string) consentMode {
	if len(policy) > 0 {
		for _, ch := range policy {
			switch ch {
			case "elicitation":
				if c.elicitation {
					return consentInline
				}
			case "widget":
				if c.uiExt {
					return consentWidget
				}
			case "console":
				if consoleEnabled {
					return consentConsole
				}
			}
		}
		if consoleEnabled {
			return consentConsole
		}
		return consentDenied
	}
	elic := c.elicitation && !ff.bypassElicitation
	ui := c.uiExt && !ff.bypassWidget
	switch {
	case elic:
		return consentInline
	case ui:
		return consentWidget
	case consoleEnabled:
		return consentConsole
	default:
		return consentDenied
	}
}

func (g *Gateway) setCaps(connID string, c clientCaps) {
	g.sessMu.Lock()
	g.byConnCaps[connID] = c
	g.sessMu.Unlock()
}
func (g *Gateway) capsOf(connID string) clientCaps {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	return g.byConnCaps[connID]
}

// setPolicy/policyOf keep the agent key's consent-channel policy per connection (stashed at
// initialize from the verified TokenInfo), mirroring byConnCaps. Guarded by the same mutex.
func (g *Gateway) setPolicy(connID string, p []string) {
	g.sessMu.Lock()
	g.byConnPolicy[connID] = p
	g.sessMu.Unlock()
}
func (g *Gateway) policyOf(connID string) []string {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	return g.byConnPolicy[connID]
}

// setConnMeta stashes the callMeta of the guarded call that triggered a widget consent, keyed by
// connection, so widgetRequestAccess/serveConsentToken (which run LATER, when the model opens the
// dialog) can build the same legible headline the elicitation dialog shows. Guarded by the same
// mutex as byConn/byConnCaps.
func (g *Gateway) setConnMeta(connID string, m callMeta) {
	g.sessMu.Lock()
	g.byConnMeta[connID] = m
	g.sessMu.Unlock()
}

// connMeta returns the callMeta stashed for a connection by setConnMeta. ok=false means no guarded
// call originated this consent (a direct request_access) — the caller falls back to the reason line.
func (g *Gateway) connMeta(connID string) (callMeta, bool) {
	g.sessMu.Lock()
	defer g.sessMu.Unlock()
	m, ok := g.byConnMeta[connID]
	return m, ok
}

// staticConsent replays a decision the human already made in the consent widget: Ask returns
// the recorded answer without further interaction, so the widget path mints through exactly
// the same Decide → MintFor pipeline (receipts included) as inline elicitation. A nil answer
// is a decline.
type staticConsent struct{ answer *controlplane.ConsentAnswer }

func (s staticConsent) Ask(controlplane.ConsentRequest) (*controlplane.ConsentAnswer, error) {
	return s.answer, nil
}

// widgetConsentInstruction is the NON-error result a guarded vendor call returns when the
// session must consent via the widget: it tells the model exactly which follow-up call
// renders the dialog. The vendor tool is NOT executed.
func (g *Gateway) widgetConsentInstruction(ctx context.Context, connID, tool string, scopes []string, meta callMeta) *mcp.CallToolResult {
	pc := g.pending.findOrCreate(g.principalOf(ctx), connID, scopes, "tool: "+tool)
	// Stash the originating call's meta so the widget (opened LATER, when the model calls
	// open_access_dialog) leads with the same legible headline the elicitation dialog shows.
	g.setConnMeta(connID, meta)
	log.Printf("🔒 %s needs [%s] — widget consent pending (request %s); told the model to call open_access_dialog", tool, strings.Join(scopes, ", "), pc.ID)
	return text(consentHeadline(g.br.AgentDisplayName(g.resumeSession(connID)), meta) + "\n" +
		"🔒 DELEGENT: consent required — '" + tool + "' needs scopes [" + strings.Join(scopes, ", ") + "] that this session does not hold. " +
		"Call the open_access_dialog tool now with {\"scopes\": [\"" + strings.Join(scopes, "\", \"") + "\"], \"reason\": \"<why the task needs this>\"} — " +
		"it shows the user a consent dialog. Retry '" + tool + "' only after the user grants.")
}

// buildWidgetPayload assembles the model-visible consent ask streamed into the widget. When a
// prior guarded tool call stashed its callMeta on this connection (setConnMeta), the payload leads
// with the SAME legible headline the elicitation dialog shows — "<agent> wants to <action> on
// <target> — <risk>." plus a Why line — and the declared intent; absent stashed meta it omits the
// headline and the widget falls back to the reason line. The headline/intent are also persisted on
// the pending record so serveConsentToken renders them after a bridged resource-read (Claude
// Desktop, which delivers neither structuredContent nor _meta to the widget).
func (g *Gateway) buildWidgetPayload(connID string, pc pendingConsent, cr controlplane.ConsentRequest) map[string]any {
	agent := g.br.AgentDisplayName(g.resumeSession(connID)) // WHO is asking, not just what for
	scopes := make([]map[string]any, len(cr.Scopes))
	for i, sc := range cr.Scopes {
		scopes[i] = map[string]any{"scope": sc.Scope, "human": sc.Human, "risk": sc.Risk, "warnings": sc.Warnings}
	}
	payload := map[string]any{
		"request_id":        pc.ID,
		"reason":            pc.Reason,
		"agent":             agent,
		"scopes":            scopes,
		"ttl_options":       ttlOptions(),
		"ttl_default_min":   ttlDefault().Minutes,
		"over_ask_warnings": cr.OverAskWarnings,
		"ungrantable":       cr.Ungrantable,
		"expires_at":        pc.ExpiresAt,
	}
	if g.grantScope == grantScopeConnection {
		payload["scope_note"] = "This grant applies to THIS conversation/connection only, for the TTL you pick."
	}
	if meta, ok := g.connMeta(connID); ok {
		headline := consentHeadline(agent, meta)
		payload["headline"] = headline
		payload["intent"] = meta.Intent
		// Persist on the record so serveConsentToken (the widget's bridged resource-read) shows
		// the same headline even where the host never delivers this payload to the widget.
		g.pending.setDisplay(pc.ID, headline, meta.Intent)
	}
	return payload
}

// widgetRequestAccess is request_access in widget mode: instead of eliciting, it mints (or
// reuses) the pending nonce and returns the ask as structuredContent — the host renders the
// tool's ui:// widget and streams this payload into it via ui/notifications/tool-result.
func (g *Gateway) widgetRequestAccess(ctx context.Context, req *mcp.CallToolRequest, a requestAccessArgs) (*mcp.CallToolResult, any, error) {
	connID := req.Session.ID()
	principal := g.principalOf(ctx)
	reason := a.Reason
	if reason == "" {
		reason = "request_access"
	}
	cr := g.cp.DescribeConsent(principal, a.Scopes, reason)
	if len(cr.Scopes) == 0 {
		msg := "Nothing granted. " + principal + " does not hold: " + strings.Join(cr.Ungrantable, ", ") +
			" — outside its own entitlements, so no consent dialog can grant it."
		log.Printf("request_access (widget) — %s", msg)
		return toolError(msg), nil, nil
	}
	pc := g.pending.findOrCreate(principal, connID, a.Scopes, reason)

	payload := g.buildWidgetPayload(connID, pc, cr)
	log.Printf("request_access (widget) — consent dialog pending, request %s scopes [%s]; blocking up to %s for the decision", pc.ID, strings.Join(a.Scopes, ", "), consentDecisionWait)

	// BLOCK until the widget's submit_consent_decision resolves this record (the host renders
	// the widget from ui/notifications/tool-input + the widget's own resources/read — it does
	// NOT need this call's result). On a decision, return the submit's own text so the model
	// proceeds immediately in the same turn — no manual retry.
	g.pending.setWaiting(pc.ID, true)
	outcome, decided := awaitConsent(ctx, pc.done, consentDecisionWait)
	g.pending.setWaiting(pc.ID, false)
	if !decided {
		// Close the race where the submit landed between our timer firing and the waiting
		// flag clearing: the buffered channel parks the outcome for exactly this drain.
		select {
		case outcome = <-pc.done:
			decided = true
		default:
		}
	}
	if decided {
		log.Printf("request_access (widget) — request %s resolved inline (granted=%v)", pc.ID, outcome.granted)
		return text(outcome.message), nil, nil
	}

	log.Printf("request_access (widget) — request %s still undecided after %s; returning the two-phase wait instruction", pc.ID, consentDecisionWait)
	return &mcp.CallToolResult{
		// Model-visible text: deliberately generic — no request_id, nothing redeemable.
		Content: []mcp.Content{&mcp.TextContent{Text: "Consent dialog shown to the user — wait for their GRANT/DENY decision; " +
			"do NOT attempt to approve on their behalf. Retry the original call only after they grant."}},
		// structuredContent is MODEL-VISIBLE: the widget needs request_id to render and
		// submit, and the id alone is harmless — redemption also requires the widget_token
		// below, which travels ONLY in _meta (the host streams _meta into the widget via
		// ui/notifications/tool-result; models never see it).
		StructuredContent: payload,
		Meta:              mcp.Meta{"delegent/consent": map[string]any{"widget_token": pc.WidgetToken}},
	}, nil, nil
}

type submitConsentArgs struct {
	RequestID   string   `json:"request_id" jsonschema:"the pending consent request id shown in the dialog"`
	WidgetToken string   `json:"widget_token,omitempty" jsonschema:"the token delivered in the request_access result _meta; proves the submission came from the consent widget"`
	Granted     []string `json:"granted" jsonschema:"the scopes the user granted; empty means DENY ALL"`
	TTLMinutes  int      `json:"ttl_minutes,omitempty" jsonschema:"how long the grant lives (default 60)"`
	BudgetUSD   float64  `json:"budget_usd,omitempty" jsonschema:"spending ceiling in USD (default 1)"`
}

// handleSubmitConsent is the widget's decision channel — but its visibility ["app"] is only
// HOST-enforced, so this handler assumes any caller may be hostile (see the package comment
// for the trust boundary). Redemption requires the _meta-only widget_token AND the same
// connection and principal that opened the request; anything unrecognized, expired, replayed,
// or mismatched is rejected. Binding mismatches get ONE uniform outward message (the log
// stays specific) so a forger learns nothing. On success it mints through the same broker
// path the elicitation dialog uses, writing the same receipts.
func (g *Gateway) handleSubmitConsent(ctx context.Context, req *mcp.CallToolRequest, a submitConsentArgs) (*mcp.CallToolResult, any, error) {
	pc, err := g.pending.consume(a.RequestID, a.WidgetToken, req.Session.ID(), g.principalOf(ctx))
	if err != nil {
		log.Printf("🔒 submit_consent_decision REJECTED — %v", err)
		if errors.Is(err, errConsentBinding) {
			return toolError("🔒 DELEGENT: consent decision rejected"), nil, nil
		}
		return toolError("🔒 DELEGENT: consent decision rejected — " + err.Error()), nil, nil
	}

	var answer *controlplane.ConsentAnswer // nil = the user declined
	if len(a.Granted) > 0 {
		ttl := ttlClampMinutes(a.TTLMinutes)
		budget := a.BudgetUSD
		if budget <= 0 {
			budget = 1
		}
		answer = &controlplane.ConsentAnswer{Granted: a.Granted, TTLMinutes: ttl, BudgetUSD: budget}
	}

	// deliveredInline: a request_access call was blocked on this record when we consumed it,
	// so the outcome below returns THROUGH that call and the model continues on its own — the
	// widget reads this flag to suppress its ui/message retry nudge.
	deliveredInline := pc.waiting

	granted, msg := g.mintPending(pc, answer)
	if !granted {
		log.Printf("🔒 widget consent %s DENIED — %s", pc.ID, msg)
		return &mcp.CallToolResult{
			Content:           []mcp.Content{&mcp.TextContent{Text: "Denied. " + msg}},
			StructuredContent: map[string]any{"granted": false, "message": msg, "delivered_inline": deliveredInline},
		}, nil, nil
	}
	log.Printf("✅ widget consent %s GRANTED [%s] — %s (delivered_inline=%v)", pc.ID, strings.Join(a.Granted, ", "), msg, deliveredInline)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: msg}},
		StructuredContent: map[string]any{"granted": true, "message": msg, "scopes": a.Granted, "delivered_inline": deliveredInline},
	}, nil, nil
}

// mintPending is the ONE mint path shared by every human consent decision on a pending record —
// the widget's submit_consent_decision AND the console's ResolvePending. The record must
// already be validated/consumed by the caller (the widget binds it to the _meta widget_token +
// connection + principal; the console binds it to the console bearer + owner filter). A nil
// answer is a decline. On any outcome it resolves the record's done channel so a request_access
// (or a console-mode vendor call) blocked on it returns in the same turn.
func (g *Gateway) mintPending(pc pendingConsent, answer *controlplane.ConsentAnswer) (granted bool, message string) {
	handle := g.resumeSession(pc.ConnID)
	nh, msg, ok := g.br.Grant(pc.Principal, handle, pc.Scopes, pc.Reason, staticConsent{answer: answer})
	if !ok {
		g.emitPending(pc, store.EventPermissionDenied, nil, msg)
		pc.resolve(consentOutcome{granted: false, message: "Denied. " + msg})
		return false, msg
	}
	if handle == "" {
		g.setSession(pc.ConnID, nh)
		log.Printf("[delegent] session %s (%s) minted for connection %s", nh, g.br.AgentDisplayName(nh), pc.ConnID)
	}
	var gScopes []string
	if answer != nil {
		gScopes = answer.Granted
	}
	g.emitPending(pc, store.EventPermissionGranted, gScopes, msg)
	pc.resolve(consentOutcome{granted: true, message: msg})
	return true, msg
}

// emitPending records a permission_granted/denied activity-log event for a decided pending
// record. The decision is made by the operator (widget submit or console resolve), so there is
// no agent auth context here — the identity fields come from the record and the resumed session.
func (g *Gateway) emitPending(pc pendingConsent, typ string, scopes []string, reason string) {
	h := g.resumeSession(pc.ConnID)
	g.emit(store.Event{
		Type: typ, TargetID: g.targetID, UserID: pc.Principal,
		SessionHandle: h, AgentName: g.br.AgentDisplayName(h),
		Tool: "", Scopes: scopes, Reason: reason,
	})
}

// serveConsentWidget serves the ui:// consent dialog template. It is a static, fully
// self-contained HTML document (inline CSS/JS, no external domains — the default Apps CSP
// blocks all outbound traffic, which is exactly right for a consent surface).
// serveConsentToken answers the widget's bridged resources/read with the calling
// connection's own latest pending request {request_id, widget_token}. Trust boundary: on
// hosts where the model can also read resources this weakens the token to conn-binding
// only — acceptable because those clients (e.g. Claude Code) use the elicitation path, and
// conn+principal binding plus the single-use nonce still hold.
func (g *Gateway) serveConsentToken(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	pc, ok := g.pending.latestForConn(req.Session.ID())
	if !ok {
		return nil, fmt.Errorf("no pending consent request for this connection")
	}
	log.Printf("[delegent] consent token served to connection %s for request %s (resources/read)", req.Session.ID(), pc.ID)
	// Full ask payload: Claude Desktop delivers neither structuredContent nor _meta to the
	// widget, so this widget-only resource carries everything the dialog needs.
	cr := g.cp.DescribeConsent(pc.Principal, pc.Scopes, pc.Reason)
	scopes := make([]map[string]any, len(cr.Scopes))
	for i, sc := range cr.Scopes {
		scopes[i] = map[string]any{"scope": sc.Scope, "human": sc.Human, "risk": sc.Risk, "warnings": sc.Warnings}
	}
	ask := map[string]any{
		"request_id": pc.ID, "widget_token": pc.WidgetToken, "reason": pc.Reason,
		"agent":  g.br.AgentDisplayName(g.resumeSession(pc.ConnID)),
		"scopes": scopes, "ttl_options": ttlOptions(), "ttl_default_min": ttlDefault().Minutes,
		"over_ask_warnings": cr.OverAskWarnings, "ungrantable": cr.Ungrantable, "expires_at": pc.ExpiresAt,
	}
	// Legible headline + intent stashed from the originating guarded call (empty on a direct
	// request_access — the widget falls back to the reason line). Additive display only.
	if pc.Headline != "" {
		ask["headline"] = pc.Headline
		ask["intent"] = pc.Intent
	}
	if g.grantScope == grantScopeConnection {
		ask["scope_note"] = "This grant applies to THIS conversation/connection only, for the TTL you pick."
	}
	body, _ := json.Marshal(ask)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI:      consentTokenURI,
		MIMEType: "application/json",
		Text:     string(body),
	}}}, nil
}

func serveConsentWidget(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	// This log line is the first breadcrumb when a host renders an empty widget box: if it
	// never appears, the host never even fetched the widget HTML (URI/mimeType mismatch).
	log.Printf("[delegent] consent widget HTML served (resources/read %s)", consentWidgetURI)
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI:      consentWidgetURI,
		MIMEType: consentWidgetMIME,
		Text:     consentWidgetHTML,
		Meta:     mcp.Meta{"ui": map[string]any{"prefersBorder": true}},
	}}}, nil
}

// consentWidgetHTML is the in-chat consent dialog. The JS speaks the MCP Apps postMessage
// bridge exactly as the official @modelcontextprotocol/ext-apps SDK does (verified against
// its source, src/message-transport.ts + src/app.ts + src/generated/schema.ts @ main):
//
//   - transport: bare JSON-RPC 2.0 objects on window.postMessage with targetOrigin "*",
//     no envelope, no MessageChannel; incoming messages are accepted only from
//     event.source === window.parent (a sandbox proxy, if any, relays transparently);
//   - handshake: the VIEW initiates — ui/initialize with params
//     {appInfo:{name,version}, appCapabilities:{}, protocolVersion:"2026-01-26"}
//     (NOT clientInfo/capabilities: the host validates against a Zod schema that REQUIRES
//     appInfo+appCapabilities, and per spec the host MUST NOT send the view anything —
//     and typically keeps the iframe hidden/zero-sized — until it has received our
//     ui/notifications/initialized). We resend ui/initialize with a fresh id until a
//     response arrives, in case our first fired before the host bridge attached;
//   - after initialized: answer host `ping` requests, ack ui/resource-teardown, and send
//     ui/notifications/size-changed like the SDK's autoResize so the host can size the frame;
//   - data in: ui/notifications/tool-result params IS the CallToolResult
//     (params.structuredContent renders the ask, params._meta carries the widget_token);
//   - decision out: bridged tools/call of submit_consent_decision, then a ui/message with
//     content as an ARRAY of content blocks (the SDK schema rejects a bare object).
//
// DENY is the default everywhere; GRANT stays disabled until the user explicitly toggles
// at least one scope.
const consentWidgetHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Delegent — Access request</title>
<style>
  :root {
    --bg: #101318; --panel: #171b22; --line: #262c37; --text: #e6e9ef; --dim: #8b94a7;
    --accent: #34d399; --accent-dim: #10552f; --danger: #f87171; --amber: #fbbf24; --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { background: var(--bg); color: var(--text);
    font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 560px; margin: 0 auto; padding: 14px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
  .head { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--line); }
  .shield { width: 26px; height: 26px; border-radius: 7px; background: var(--accent-dim); color: var(--accent);
    display: flex; align-items: center; justify-content: center; font-size: 14px; }
  .head h1 { font-size: 14px; font-weight: 600; }
  .head .sub { font-size: 11px; color: var(--dim); }
  .body { padding: 14px 16px; }
  .reason { color: var(--dim); font-size: 12.5px; margin-bottom: 12px; }
  .reason b { color: var(--text); font-weight: 600; }
  .headline { color: var(--text); font-size: 13.5px; font-weight: 600; line-height: 1.4; margin-bottom: 12px; }
  .headline .why { color: var(--dim); font-size: 12.5px; font-weight: 400; margin-top: 4px; }
  .warn { background: rgba(251,191,36,.08); border: 1px solid rgba(251,191,36,.35); color: var(--amber);
    border-radius: 8px; padding: 8px 10px; font-size: 12px; margin-bottom: 10px; }
  .scope { border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; margin-bottom: 8px;
    display: flex; align-items: center; gap: 10px; }
  .scope.on { border-color: var(--accent); background: rgba(52,211,153,.06); }
  .scope .info { flex: 1; min-width: 0; }
  .scope .name { font-family: var(--mono); font-size: 12.5px; font-weight: 600; }
  .scope .human { color: var(--dim); font-size: 12px; margin-top: 1px; }
  .scope .swarn { color: var(--amber); font-size: 11.5px; margin-top: 2px; }
  .badge { font-size: 10px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
    border-radius: 5px; padding: 2px 6px; flex: none; }
  .badge.low { color: var(--accent); background: rgba(52,211,153,.12); }
  .badge.medium { color: var(--amber); background: rgba(251,191,36,.12); }
  .badge.high { color: var(--danger); background: rgba(248,113,113,.12); }
  .toggle { display: flex; flex: none; border: 1px solid var(--line); border-radius: 7px; overflow: hidden; }
  .toggle button { border: 0; background: transparent; color: var(--dim); font: inherit; font-size: 11px;
    font-weight: 700; padding: 5px 10px; cursor: pointer; }
  .toggle button.deny.active { background: rgba(248,113,113,.16); color: var(--danger); }
  .toggle button.grant.active { background: rgba(52,211,153,.16); color: var(--accent); }
  .controls { display: flex; gap: 10px; margin: 12px 0 4px; }
  .field { flex: 1; }
  .field label { display: block; font-size: 11px; color: var(--dim); margin-bottom: 4px; }
  .field select, .field input { width: 100%; background: var(--bg); color: var(--text);
    border: 1px solid var(--line); border-radius: 7px; padding: 7px 9px; font: inherit; font-size: 13px; }
  .actions { display: flex; gap: 10px; padding: 12px 16px; border-top: 1px solid var(--line); }
  .btn { border: 0; border-radius: 8px; font: inherit; font-weight: 700; padding: 10px 14px; cursor: pointer; }
  .btn.grant { flex: 1; background: var(--accent); color: #06281a; }
  .btn.grant:disabled { background: var(--line); color: var(--dim); cursor: not-allowed; }
  .btn.denyall { background: transparent; color: var(--danger); border: 1px solid rgba(248,113,113,.4); }
  .foot { padding: 8px 16px 12px; color: var(--dim); font-size: 11px; font-family: var(--mono); }
  .status { padding: 12px 16px; font-size: 13px; }
  .status.ok { color: var(--accent); }
  .status.bad { color: var(--danger); }
  .loading { padding: 24px 16px; color: var(--dim); font-size: 13px; text-align: center; }
</style>
</head>
<body>
<div class="wrap"><div class="card" id="card">
  <div style="padding:12px 16px;border-bottom:1px solid #333;font-weight:700;font-size:14px;color:#fff">🚪 Delegent — access request</div>
  <div class="loading" id="boot">Waiting for the access request&hellip;<br><span id="diag" style="font-size:11px;opacity:.7">script loaded; bridge: connecting</span></div>
</div></div>
<script>
(function () {
  "use strict";
  var nextId = 1, pending = {}, state = null, submitted = false;

  // On-screen diagnostics: when a host renders an empty/blank widget, this line is the
  // difference between guessing and knowing which handshake step stalled.
  function diag(msg) {
    var d = document.getElementById("diag");
    if (d) d.textContent = msg;
  }
  window.onerror = function (msg) { diag("script error: " + msg); };

  // Transport = the SDK's PostMessageTransport: bare JSON-RPC 2.0 on window.postMessage,
  // targetOrigin "*", no envelope. Incoming messages accepted only from window.parent.
  function post(msg) { window.parent.postMessage(msg, "*"); }
  function call(method, params) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending[id] = { resolve: resolve, reject: reject };
      post({ jsonrpc: "2.0", id: id, method: method, params: params });
    });
  }

  window.addEventListener("message", function (ev) {
    if (ev.source !== window.parent) return; // SDK transports validate event.source
    var m = ev.data;
    if (!m || m.jsonrpc !== "2.0") { return; } // non-JSON-RPC traffic: ignore silently
    if (m.method) diag("bridge: got " + m.method);
    if (m.id !== undefined && m.method === undefined) { // a response to one of our requests
      var p = pending[m.id];
      if (p) { delete pending[m.id]; if (m.error) { p.reject(m.error); } else { p.resolve(m.result); } }
      return;
    }
    if (m.method === "ping" && m.id !== undefined) { // host health check (MCP core)
      post({ jsonrpc: "2.0", id: m.id, result: {} });
      return;
    }
    if (m.method === "ui/notifications/tool-input") {
      // The request_access call now BLOCKS server-side until the user decides, so no
      // tool-result will arrive while this dialog matters. tool-input is the host's signal
      // that the call is in flight — fetch the ask ourselves via resources/read.
      fetchAsk("tool-input received");
      return;
    }
    if (m.method === "ui/notifications/tool-result") {
      // Spec: params IS the CallToolResult (SDK McpUiToolResultNotification) — but hosts
      // differ in the wild, so probe common wrappings too. The widget_token rides ONLY in
      // the result _meta — the host delivers _meta to this widget but never to the model.
      var p = m.params || {};
      var cands = [p, p.result, p.toolResult, p.callToolResult, p.data];
      for (var ci = 0; ci < cands.length; ci++) {
        var c = cands[ci];
        var sc = c && c.structuredContent;
        if (sc && sc.request_id && !submitted) {
          var meta = (c && c._meta) || p._meta;
          var dc = meta && meta["delegent/consent"];
          gotPayload(sc, (dc && dc.widget_token) || "");
          return;
        }
      }
      // Claude Desktop strips structuredContent/_meta and serializes the payload as an
      // extra JSON text block in content — recover it from there.
      var blocks = p.content || [];
      for (var bi = 0; bi < blocks.length; bi++) {
        if (!blocks[bi] || blocks[bi].type !== "text") continue;
        try {
          var parsed = JSON.parse(blocks[bi].text);
          if (parsed && parsed.request_id && !submitted) { gotPayload(parsed, ""); return; }
        } catch (e) { /* not JSON — the human-readable block */ }
      }
      // No consent payload found — show the shape we actually received, so the next
      // screenshot diagnoses the host's dialect instead of guessing.
      try {
        var shape = Object.keys(p).map(function (k) {
          var v = p[k];
          return k + ":" + (v === null ? "null" : Array.isArray(v) ? "array(" + v.length + ")" : typeof v === "object" ? "{" + Object.keys(v).join(" ") + "}" : typeof v);
        }).join(", ");
        var blocksDump = (p.content || []).map(function (b, i) {
          return "[" + i + "] " + (b && b.type) + ": " + String(b && (b.text !== undefined ? b.text : JSON.stringify(b))).slice(0, 120);
        }).join(" | ");
        diag("v3 no consent payload — shape: " + shape.slice(0, 200) + " — blocks: " + blocksDump.slice(0, 600));
      } catch (e) { diag("tool-result had no consent payload (unparsable)"); }
      fetchAsk("tool-result carried no payload");
      return;
    }
    if (m.method === "ui/resource-teardown") { // host is destroying us; ack so it may proceed
      post({ jsonrpc: "2.0", id: m.id, result: {} });
      return;
    }
  });

  // ---- MCP Apps handshake (view initiates; host reveals only after initialized) ----
  // The official host bridge validates ui/initialize params against a schema REQUIRING
  // appInfo + appCapabilities. clientInfo/capabilities are included too as harmless extras
  // for hosts that implemented the spec's informal example; schema hosts strip unknown keys.
  var appInfo = { name: "delegent-consent", version: "0.3.0" };
  var initDone = false, initTries = 0;
  function initialize() {
    if (initDone) return;
    if (++initTries > 12) { diag("bridge: no ui/initialize response after " + (initTries - 1) + " tries — host bridge absent?"); return; }
    diag("bridge: sending ui/initialize (try " + initTries + ")");
    call("ui/initialize", {
      protocolVersion: "2026-01-26",
      appInfo: appInfo,
      appCapabilities: {},
      clientInfo: appInfo,
      capabilities: {}
    }).then(function () {
      if (initDone) return;
      initDone = true;
      post({ jsonrpc: "2.0", method: "ui/notifications/initialized", params: {} });
      diag("bridge: initialized — waiting for the consent payload (tool-result)");
      startSizeReports();
    }).catch(function (e) {
      initDone = true; // a real rejection: retrying the same shape will not help
      diag("bridge: ui/initialize rejected: " + (e && e.message || JSON.stringify(e)));
    });
    // Resend with a fresh id if no response yet: our first request may have fired
    // before the host attached its bridge listener (the host answers duplicates).
    setTimeout(initialize, 800);
  }
  initialize();
  // Fallback poll: keep self-fetching until the ask arrives — the blocked request_access
  // call sends no tool-result, and some hosts deliver tool-input unreliably.
  var pollTries = 0;
  (function poll() {
    setTimeout(function () {
      if (state || submitted || ++pollTries > 15) return;
      fetchAsk("no payload yet (poll " + pollTries + ")");
      poll();
    }, 2000);
  })();

  // ---- ui/notifications/size-changed, as the SDK's autoResize sends them ----
  // Hosts size (and some only then fully reveal) the iframe from these reports.
  function startSizeReports() {
    var scheduled = false, lastW = 0, lastH = 0;
    function report() {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(function () {
        scheduled = false;
        var html = document.documentElement;
        var orig = html.style.height;
        html.style.height = "max-content"; // measure content, not viewport (SDK technique)
        var h = Math.ceil(html.getBoundingClientRect().height);
        html.style.height = orig;
        var w = Math.ceil(window.innerWidth);
        if (w !== lastW || h !== lastH) {
          lastW = w; lastH = h;
          post({ jsonrpc: "2.0", method: "ui/notifications/size-changed", params: { width: w, height: h } });
        }
      });
    }
    report();
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(report);
      ro.observe(document.documentElement);
      ro.observe(document.body);
    }
  }

  // ---- rendering ----
  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt !== undefined) e.textContent = txt;
    return e;
  }
  function riskClass(r) {
    r = String(r || "").toLowerCase();
    return r === "high" || r === "critical" ? "high" : (r === "medium" ? "medium" : "low");
  }

  // gotPayload renders the consent ask; when the host stripped _meta (Claude Desktop), the
  // token is recovered via a bridged resources/read — a widget-only channel on such hosts.
  // fetchAsk pulls the full pending request over the bridge — the widget-only channel that
  // works even when the host (Claude Desktop) delivers no structuredContent/_meta at all.
  function fetchAsk(why) {
    if (state) return;
    diag(why + " — fetching the request via resources/read…");
    call("resources/read", { uri: "ui://delegent/consent-token" }).then(function (res) {
      try {
        var t = JSON.parse(res.contents[0].text);
        if (t.request_id && !submitted) { gotPayload(t, t.widget_token || ""); diag("ready"); }
      } catch (e) { diag("fetched request unparsable"); }
    }).catch(function (e) { diag("fetch failed: " + (e && e.message || JSON.stringify(e))); });
  }

  function gotPayload(sc, token) {
    state = { payload: sc, granted: {}, token: token || "" };
    render();
    if (!state.token) {
      diag("recovering widget token via resources/read…");
      call("resources/read", { uri: "ui://delegent/consent-token" }).then(function (res) {
        try {
          var t = JSON.parse(res.contents[0].text);
          if (t.request_id === state.payload.request_id) { state.token = t.widget_token; diag("token recovered — ready"); }
          else { diag("token recovery mismatch: got request " + t.request_id); }
        } catch (e) { diag("token recovery unparsable"); }
      }).catch(function (e) { diag("token recovery failed: " + (e && e.message || JSON.stringify(e))); });
    }
  }

  function render() {
    var p = state.payload, card = document.getElementById("card");
    card.textContent = "";

    var head = el("div", "head");
    var shield = el("div", "shield", "◆");
    var ht = el("div");
    ht.appendChild(el("h1", null, "Access request"));
    ht.appendChild(el("div", "sub", "Delegent — nothing is granted until you decide"));
    head.appendChild(shield); head.appendChild(ht);
    card.appendChild(head);

    var body = el("div", "body");
    if (p.headline) {
      // Legible headline — the SAME line the elicitation dialog leads with: first line is the
      // action + risk ("<agent> wants to <action> on <target> — <risk>."), any following line
      // (a "Why:" intent line) shown dimmer below. consentHeadline joins these with "\n".
      var hlines = String(p.headline).split("\n");
      var headline = el("div", "headline", hlines[0]);
      for (var hi = 1; hi < hlines.length; hi++) {
        if (hlines[hi]) headline.appendChild(el("div", "why", hlines[hi]));
      }
      body.appendChild(headline);
    } else {
      // Fallback (a direct request_access with no originating tool call): the old reason line.
      var reason = el("div", "reason");
      reason.appendChild(document.createTextNode("The agent asks for the access below. Reason: "));
      var b = el("b", null, p.reason || "(none given)");
      reason.appendChild(b);
      body.appendChild(reason);
    }

    if (p.agent) {
      var agentRow = el("div", "reason");
      agentRow.appendChild(document.createTextNode("Requesting agent: "));
      agentRow.appendChild(el("b", null, p.agent));
      body.appendChild(agentRow);
    }
    if (p.scope_note) body.appendChild(el("div", "reason", p.scope_note));

    (p.over_ask_warnings || []).forEach(function (w) { body.appendChild(el("div", "warn", w)); });
    if (p.ungrantable && p.ungrantable.length) {
      body.appendChild(el("div", "warn", "Not offered — outside your entitlements: " + p.ungrantable.join(", ")));
    }

    (p.scopes || []).forEach(function (sc) {
      var row = el("div", "scope");
      var info = el("div", "info");
      info.appendChild(el("div", "name", sc.scope));
      if (sc.human) info.appendChild(el("div", "human", sc.human));
      (sc.warnings || []).forEach(function (w) { info.appendChild(el("div", "swarn", "⚠ " + w)); });
      row.appendChild(info);
      row.appendChild(el("span", "badge " + riskClass(sc.risk), sc.risk || "low"));

      var tg = el("div", "toggle");
      var deny = el("button", "deny active", "DENY");
      var grant = el("button", "grant", "GRANT");
      deny.type = grant.type = "button";
      deny.onclick = function () {
        delete state.granted[sc.scope];
        deny.classList.add("active"); grant.classList.remove("active"); row.classList.remove("on");
        refresh();
      };
      grant.onclick = function () {
        state.granted[sc.scope] = true;
        grant.classList.add("active"); deny.classList.remove("active"); row.classList.add("on");
        refresh();
      };
      tg.appendChild(deny); tg.appendChild(grant);
      row.appendChild(tg);
      body.appendChild(row);
    });

    var controls = el("div", "controls");
    var f1 = el("div", "field");
    f1.appendChild(el("label", null, "How long?"));
    var ttl = document.createElement("select");
    var ttlOpts = (p.ttl_options && p.ttl_options.length) ? p.ttl_options : [{label:"15m",minutes:15},{label:"1h",minutes:60},{label:"8h",minutes:480}];
    var ttlDefault = p.ttl_default_min || 60;
    ttlOpts.forEach(function (o) {
      var opt = document.createElement("option");
      opt.value = String(o.minutes); opt.textContent = o.label;
      if (o.minutes === ttlDefault) opt.selected = true;
      ttl.appendChild(opt);
    });
    f1.appendChild(ttl);
    var f2 = el("div", "field");
    f2.appendChild(el("label", null, "Budget (USD)"));
    var budget = document.createElement("input");
    budget.type = "number"; budget.min = "0"; budget.step = "0.5"; budget.value = "1";
    f2.appendChild(budget);
    controls.appendChild(f1); controls.appendChild(f2);
    body.appendChild(controls);
    card.appendChild(body);

    var actions = el("div", "actions");
    var grantBtn = el("button", "btn grant", "Grant selected");
    var denyBtn = el("button", "btn denyall", "Deny all");
    grantBtn.type = denyBtn.type = "button";
    grantBtn.disabled = true;
    grantBtn.onclick = function () { submit(Object.keys(state.granted), ttl, budget); };
    denyBtn.onclick = function () { submit([], ttl, budget); };
    actions.appendChild(grantBtn); actions.appendChild(denyBtn);
    card.appendChild(actions);

    card.appendChild(el("div", "foot", "request " + p.request_id));

    function refresh() {
      var n = Object.keys(state.granted).length;
      grantBtn.disabled = n === 0;
      grantBtn.textContent = n === 0 ? "Grant selected" : "Grant " + n + " scope" + (n === 1 ? "" : "s");
    }
    state.refresh = refresh;
  }

  function submit(granted, ttlSel, budgetInput) {
    if (submitted) return;
    submitted = true;
    var card = document.getElementById("card");
    var st = el("div", "status", granted.length ? "Submitting your decision…" : "Denying…");
    card.textContent = "";
    card.appendChild(st);
    call("tools/call", {
      name: "submit_consent_decision",
      arguments: {
        request_id: state.payload.request_id,
        widget_token: state.token,
        granted: granted,
        ttl_minutes: parseInt(ttlSel.value, 10) || 60,
        budget_usd: parseFloat(budgetInput.value) || 1
      }
    }).then(function (res) {
      var msg = "";
      if (res && res.content && res.content.length && res.content[0].text) msg = res.content[0].text;
      var ok = granted.length > 0 && res && !res.isError;
      // delivered_inline: the blocked request_access call already returned the outcome to
      // the model — it is continuing on its own, so a ui/message nudge would only clutter
      // the input box.
      var inline = !!(res && res.structuredContent && res.structuredContent.delivered_inline);
      st.className = "status " + (ok ? "ok" : "bad");
      if (ok) {
        st.textContent = inline ? "✓ Granted — the agent is continuing." : "✓ Granted. " + msg;
        if (!inline) {
          // Timeout path only: the blocked call already gave up, so nudge the agent to retry
          // the original call — the grant is already minted server-side.
          // content MUST be an array of content blocks (SDK McpUiMessageRequest schema).
          call("ui/message", {
            role: "user",
            content: [{ type: "text", text: "I granted access (" + granted.join(", ") + ") in the Delegent consent dialog — please retry the original call now." }]
          }).catch(function () { /* host may not support ui/message; the text above suffices */ });
        }
      } else {
        st.textContent = granted.length ? "✗ " + (msg || "Rejected.") : "✗ Denied. Nothing was granted.";
      }
    }).catch(function (err) {
      st.className = "status bad";
      st.textContent = "✗ Submission failed: " + (err && err.message ? err.message : "bridge error");
    });
  }
})();
</script>
</body>
</html>
`
