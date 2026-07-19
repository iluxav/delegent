// Activity log: the operator-facing, append-only event stream this gateway emits alongside
// serving traffic. Distinct from receipts (authority decisions), an event carries the caller's
// identity (key_prefix/key_name, resolved IP, client), the tool params/results, and every
// connection/response — enough for the console to render a filterable timeline. Emission is
// strictly BEST-EFFORT: it runs in a goroutine and never blocks or fails the request it records.
package gateway

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"delegent.dev/gateway/store"
)

// defaultLogPayloadMax caps a captured params/result JSON payload (DELEGENT_LOG_PAYLOAD_MAX).
const defaultLogPayloadMax = 8192

// logPayloadsFromEnv reads DELEGENT_LOG_PAYLOADS once at construction. Payload capture is ON by
// default; "off"/"0"/"false"/"no" (any case) disables capturing tool params + results, so the
// events carry only metadata (never vendor data).
func logPayloadsFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DELEGENT_LOG_PAYLOADS"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

// logPayloadMaxFromEnv reads DELEGENT_LOG_PAYLOAD_MAX once: a positive byte cap, else the 8192
// default. Params/result JSON longer than this is stored as a {"_truncated":N} marker.
func logPayloadMaxFromEnv() int {
	if v := os.Getenv("DELEGENT_LOG_PAYLOAD_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultLogPayloadMax
}

// keyIdentityFromContext reads back the key identity + resolved IP that makeVerifier threaded
// through the auth TokenInfo Extra. Empty strings when auth is off (no TokenInfo).
func keyIdentityFromContext(ctx context.Context) (keyPrefix, keyName, remoteIP string) {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil || ti.Extra == nil {
		return "", "", ""
	}
	get := func(k string) string {
		if v, ok := ti.Extra[k].(string); ok {
			return v
		}
		return ""
	}
	return get("key_prefix"), get("key_name"), get("remote_ip")
}

// channelPolicyFromContext reads the agent key's consent-channel policy that makeVerifier
// threaded through the auth TokenInfo Extra. Nil (= auto) when auth is off or no policy is set.
func channelPolicyFromContext(ctx context.Context) []string {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil || ti.Extra == nil {
		return nil
	}
	if p, ok := ti.Extra["consent_channels"].([]string); ok {
		return p
	}
	return nil
}

// eventBase returns an Event pre-filled with the identity fields common to every activity-log
// entry on this connection: the operating user, the key prefix/name and resolved IP (from the
// verified token), the target, and — when a session exists on connID — its handle and the
// requesting agent's display name. connID may be "" for pre-session events (a connection with
// no grant yet reads as "new agent connection").
func (g *Gateway) eventBase(ctx context.Context, connID string) store.Event {
	e := store.Event{TargetID: g.targetID, UserID: g.principalOf(ctx)}
	e.KeyPrefix, e.KeyName, e.RemoteIP = keyIdentityFromContext(ctx)
	if connID != "" {
		h := g.resumeSession(connID)
		e.SessionHandle = h
		e.AgentName = g.br.AgentDisplayName(h)
	} else {
		e.AgentName = g.br.AgentDisplayName("")
	}
	return e
}

// emit records one activity-log event. Best-effort by contract: it never blocks the request and
// never propagates an error — a failed append is logged and dropped. No-op when no store is
// wired (stdio/dev, unit tests without a store).
func (g *Gateway) emit(e store.Event) {
	if g.st == nil {
		return
	}
	// Stamp the time at the ORDERED call site, not inside the async goroutine — otherwise the
	// per-emit goroutines persist in nondeterministic order and scramble the timeline.
	if e.CreatedAt == 0 {
		e.CreatedAt = nowMillis()
	}
	// Detach the payload/scope slices so a caller reusing an arg buffer can't race the goroutine.
	e.Params = cloneRaw(e.Params)
	e.Result = cloneRaw(e.Result)
	if e.Scopes != nil {
		e.Scopes = append([]string(nil), e.Scopes...)
	}
	go func() {
		defer func() {
			if r := recover(); r != nil { // a detached goroutine panic must never crash the process
				log.Printf("[delegent] activity-log emit panicked (%s): %v", e.Type, r)
			}
		}()
		if err := g.st.AppendEvent(context.Background(), &e); err != nil {
			log.Printf("[delegent] activity-log append failed (%s): %v", e.Type, err)
		}
	}()
}

func cloneRaw(r json.RawMessage) json.RawMessage {
	if r == nil {
		return nil
	}
	return append(json.RawMessage(nil), r...)
}

// capPayload returns the JSON to persist for a params/result payload, honoring the payloads flag
// and the size cap: nil when capture is disabled or the input is empty, a {"_truncated":N}
// marker when the payload exceeds payloadMax, else the payload verbatim.
func (g *Gateway) capPayload(raw json.RawMessage) json.RawMessage {
	if !g.logPayloads || len(raw) == 0 {
		return nil
	}
	max := g.payloadMax
	if max <= 0 {
		max = defaultLogPayloadMax
	}
	if len(raw) > max {
		marker, _ := json.Marshal(map[string]int{"_truncated": len(raw)})
		return marker
	}
	return raw
}

// capIntent bounds a declared _delegent_intent to the same byte cap as a logged payload, so an
// over-long (or adversarial) intent can never blow up the activity log. Empty stays empty — the
// field is fail-soft: a missing intent is simply "", never an error and never a placeholder.
func (g *Gateway) capIntent(s string) string {
	if s == "" {
		return ""
	}
	max := g.payloadMax
	if max <= 0 {
		max = defaultLogPayloadMax
	}
	if len(s) > max {
		return s[:max]
	}
	return s
}

// toolCallEvent builds the activity-log event for an inbound vendor tool call, stamping the
// agent's declared intent (bounded) so EVERY call carries WHY — including one that sailed through
// under an existing grant with no consent prompt. params are the raw inbound arguments (captured
// per the payloads flag). Caller emits it.
func (g *Gateway) toolCallEvent(ctx context.Context, connID, name, intent string, params json.RawMessage) store.Event {
	e := g.eventBase(ctx, connID)
	e.Type = store.EventToolCall
	e.Tool = name
	e.Intent = g.capIntent(intent)
	e.Params = g.capPayload(params)
	return e
}

// capValue marshals v and runs it through capPayload — the entry point for a result (or any
// non-RawMessage) payload. Returns nil when capture is off, v is nil, or marshalling fails.
func (g *Gateway) capValue(v any) json.RawMessage {
	if !g.logPayloads || v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return g.capPayload(b)
}

// remoteIP resolves the caller's IP for the activity log: the first hop of X-Forwarded-For when
// present (a proxy set it), else the connection's RemoteAddr — port stripped in both cases.
func remoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); first != "" {
			return stripPort(first)
		}
	}
	return stripPort(r.RemoteAddr)
}

// stripPort removes a trailing :port from a host:port, leaving a bare IP/host unchanged.
func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
