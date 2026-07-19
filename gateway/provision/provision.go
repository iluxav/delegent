// Package provision turns a reviewed tool classification into a fully wired target: the
// adapter (enforcement rules) and advisor (human-facing scope descriptions) documents, the
// sealed credential, the target row, and the owner's entitlement ceiling. It is the shared
// core under every create-target surface — the SaaS console API and the local CLI — so the
// wiring a target gets does not depend on which front door created it.
package provision

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sort"
	"strings"

	"delegent.dev/gateway/id"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/store"
)

// Secrets is the sealed-secret port provision needs (satisfied by secretstore.DB).
type Secrets interface {
	Get(ctx context.Context, ref string) (string, error)
	Put(ctx context.Context, ref, secret string) error
	Delete(ctx context.Context, ref string) error
}

// RootKeys ensures a principal's root signing key exists (satisfied by rootkeys.Store).
type RootKeys interface {
	Ensure(ctx context.Context, user string) (string, error)
}

// ToolSpec is the per-tool policy row shared by target creation and policy updates (and the
// adapter/advisor builders). Semantics is OPTIONAL, DISPLAY-ONLY curation: it rides inside the
// adapter doc's `semantics` section and NEVER gates authority. A zero Semantics is seeded on
// write with a name-heuristic default so the stored doc is always populated.
type ToolSpec struct {
	Name      string                   `json:"name"`
	Effect    string                   `json:"effect"`
	Scope     string                   `json:"scope"`
	Semantics introspect.ToolSemantics `json:"semantics,omitempty"`
	// Description is the tool's human-facing description as reported by the MCP server. Like
	// Semantics it is DISPLAY-ONLY: it rides in the adapter doc's `descriptions` section and NEVER
	// gates authority. Empty when the operator/introspect didn't supply one.
	Description string `json:"description,omitempty"`
}

// FromDraft converts an introspection draft into the ToolSpec rows CreateTarget consumes,
// accepting every drafted classification as-is (the CLI's "trust the draft" path — a console
// lets the operator curate first).
func FromDraft(tools []introspect.DraftTool) []ToolSpec {
	out := make([]ToolSpec, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolSpec{Name: t.Name, Effect: t.Effect, Scope: t.Scope, Semantics: t.Semantics, Description: t.Description})
	}
	return out
}

// CreateTargetInput describes one target to provision. Exactly one of Credential (a pasted
// static secret; sealed under cred:<id>) or OAuthHandle (a completed target-less pending OAuth
// row to promote) may be set; both empty provisions a credential-less target.
type CreateTargetInput struct {
	ID          string // slugged by CreateTarget
	Name        string
	Kind        string // "mcp" (default) | "rest"
	Endpoint    string
	Credential  string
	OAuthHandle string
	Owner       string // user id that will own the target and hold its entitlement
	Tools       []ToolSpec
}

// CreateTargetResult reports what was provisioned.
type CreateTargetResult struct {
	ID     string   `json:"id"`
	Owner  string   `json:"owner"`
	Scopes []string `json:"scopes"`
	Tools  int      `json:"tools"`
}

// CreateTarget provisions the full target wiring in dependency order: adapter + advisor docs,
// sealed credential (or promoted OAuth token), the target row, its OAuthClient row (if any),
// and the owner's entitlement over every classified scope. Unknown tools are left out of the
// adapter so they fall through to the `unknown` default and are refused.
func CreateTarget(ctx context.Context, st store.Store, secrets Secrets, in CreateTargetInput) (*CreateTargetResult, error) {
	in.ID = Slug(in.ID)
	if in.ID == "" || in.Endpoint == "" || in.Owner == "" {
		return nil, errors.New("id, endpoint, and owner are required")
	}
	if in.Kind == "" {
		in.Kind = "mcp"
	}

	// the scope set the owner will hold (every classified scope + connect)
	scopeSet := map[string]bool{"mcp:connect": true}
	for _, t := range in.Tools {
		if t.Scope != "" && !IsUnknown(t.Effect) {
			scopeSet[t.Scope] = true
		}
	}
	scopes := SortedKeys(scopeSet)

	SeedSemantics(in.Tools)

	// 1. adapter (classify rules) + 2. advisor (scope descriptions) — written before the target
	//    that references them (FK order).
	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: in.ID, Name: in.Name, Doc: BuildAdapter(in.ID, in.Tools)}); err != nil {
		return nil, err
	}
	if err := st.PutAdvisor(ctx, &store.AdvisorDoc{ID: in.ID, Name: in.Name, Doc: BuildAdvisor(in.ID, in.Name, in.Tools, scopes)}); err != nil {
		return nil, err
	}

	// 3. the credential: promote a pending OAuth token, or seal the pasted static secret.
	credRef, credKind := "", ""
	var oauthClient *store.OAuthClient
	switch {
	case in.OAuthHandle != "":
		ref, oc, err := PromoteOAuthPending(ctx, st, secrets, in.OAuthHandle, in.ID)
		if err != nil {
			return nil, err
		}
		credRef, credKind, oauthClient = ref, "oauth2", oc
	case in.Credential != "":
		credRef = "cred:" + in.ID
		if err := secrets.Put(ctx, credRef, in.Credential); err != nil {
			return nil, err
		}
	}

	// 4. the target, owned by the operator
	if err := st.PutTarget(ctx, &store.Target{
		ID: in.ID, Name: in.Name, Kind: in.Kind, Endpoint: in.Endpoint,
		CredentialRef: credRef, CredentialKind: credKind, AdapterID: in.ID, AdvisorID: in.ID, Owner: in.Owner, Enabled: true,
	}); err != nil {
		return nil, err
	}

	// 4b. the OAuthClient row references the target, so it is written AFTER the target exists
	//     (relational backends enforce that order as a foreign key).
	if oauthClient != nil {
		if err := st.PutOAuthClient(ctx, oauthClient); err != nil {
			return nil, err
		}
	}

	// 5. the owner's entitlement ceiling on this target — every classified scope
	if err := st.PutEntitlement(ctx, &store.Entitlement{UserID: in.Owner, TargetID: in.ID, Scopes: scopes}); err != nil {
		return nil, err
	}

	return &CreateTargetResult{ID: in.ID, Owner: in.Owner, Scopes: scopes, Tools: len(in.Tools)}, nil
}

// PromoteOAuthPending moves a target-less pending OAuth registration onto a freshly-created
// target: it consumes the pending row (single-use), re-seals the obtained TokenSet under the
// target's credential ref ("cred:<id>") so oauthSource can refresh it, re-seals the client
// secret (if any) under "oauth_client:<id>", and returns the credential ref AND the OAuthClient
// row to persist — the caller writes that row only AFTER the target exists, because
// oauth_clients.target_id is a foreign key into targets(id). Once promoted, the old per-state
// pending blobs are deleted so no unreferenced live copy of the vendor refresh token survives —
// best-effort: a delete failure is logged but does NOT fail the (already valid) promotion.
func PromoteOAuthPending(ctx context.Context, st store.Store, secrets Secrets, handle, targetID string) (string, *store.OAuthClient, error) {
	pend, err := st.TakeOAuthPending(ctx, handle) // read-and-delete: single-use promotion
	if err != nil {
		return "", nil, errors.New("unknown oauth handle")
	}
	if pend.TokenRef == "" {
		return "", nil, errors.New("OAuth consent not completed")
	}

	// Promote the token: the whole TokenSet JSON is re-sealed under cred:<id> (NOT just the
	// access token — the full TokenSet must live there so oauthSource can refresh it).
	tokenJSON, err := secrets.Get(ctx, pend.TokenRef)
	if err != nil {
		return "", nil, errors.New("pending oauth token unavailable")
	}
	credRef := "cred:" + targetID
	if err := secrets.Put(ctx, credRef, tokenJSON); err != nil {
		return "", nil, err
	}

	clientSecretRef := ""
	if pend.ClientSecretRef != "" {
		sec, err := secrets.Get(ctx, pend.ClientSecretRef)
		if err != nil {
			return "", nil, errors.New("pending client secret unavailable")
		}
		clientSecretRef = "oauth_client:" + targetID
		if err := secrets.Put(ctx, clientSecretRef, sec); err != nil {
			return "", nil, err
		}
	}

	oc := &store.OAuthClient{
		TargetID:        targetID,
		AuthEndpoint:    pend.AuthEndpoint,
		TokenEndpoint:   pend.TokenEndpoint,
		ClientID:        pend.ClientID,
		ClientSecretRef: clientSecretRef,
		Scopes:          pend.Scopes,
		RedirectURI:     pend.RedirectURI,
	}

	if err := secrets.Delete(ctx, pend.TokenRef); err != nil {
		log.Printf("⚠️ provision: promote oauth %q: delete pending token %q: %v", targetID, pend.TokenRef, err)
	}
	if pend.ClientSecretRef != "" {
		if err := secrets.Delete(ctx, pend.ClientSecretRef); err != nil {
			log.Printf("⚠️ provision: promote oauth %q: delete pending client secret %q: %v", targetID, pend.ClientSecretRef, err)
		}
	}
	return credRef, oc, nil
}

// EnsureUser resolves the operator by external (auth) id, creating the user with a fresh sealed
// root signing key on first sight. Returns the internal user id. Idempotent; on an existing
// user it refreshes email/name but never touches the key.
func EnsureUser(ctx context.Context, st store.Store, keys RootKeys, externalID, email, name string) (string, error) {
	if u, err := st.GetUserByExternal(ctx, externalID); err == nil {
		u.Email, u.Name = email, name
		if err := st.PutUser(ctx, u); err != nil {
			return "", err
		}
		return u.ID, nil
	}
	uid := id.New("usr")
	if err := st.PutUser(ctx, &store.User{ID: uid, ExternalID: externalID, Email: email, Name: name}); err != nil {
		return "", err
	}
	if _, err := keys.Ensure(ctx, uid); err != nil {
		return "", err
	}
	return uid, nil
}

// --- adapter/advisor document builders ---

// BuildAdapter emits an adapter document core/loader can parse: the standard MCP handshake and
// reverse-channel preamble (so connect is cheap and server->client channels are denied by
// default), plus one body-aware rule per classified tool. Unknown tools are omitted, so they
// fall through to the `unknown` default and are refused.
func BuildAdapter(id string, tools []ToolSpec) json.RawMessage {
	rule := func(rid, method, name, effect string, scopes []string) map[string]any {
		body := map[string]any{"method": method}
		if name != "" {
			body["params.name"] = name
		}
		return map[string]any{
			"id":     rid,
			"match":  map[string]any{"method": "POST", "path": "/mcp", "body": body},
			"effect": effect,
			"scopes": scopes,
		}
	}
	sseRule := func(rid, method, effect string, scopes []string) map[string]any {
		return map[string]any{
			"id":     rid,
			"match":  map[string]any{"method": "SSE", "path": "/mcp", "body": map[string]any{"method": method}},
			"effect": effect,
			"scopes": scopes,
		}
	}

	classify := []map[string]any{
		rule("mcp.initialize", "initialize", "", "read", []string{"mcp:connect"}),
		rule("mcp.ping", "ping", "", "read", []string{"mcp:connect"}),
		rule("mcp.tools.list", "tools/list", "", "read", []string{"mcp:connect"}),
		rule("mcp.resources.list", "resources/list", "", "read", []string{"mcp:connect"}),
	}
	for _, t := range tools {
		if t.Scope == "" || IsUnknown(t.Effect) {
			continue
		}
		classify = append(classify, rule("tool."+t.Name, "tools/call", t.Name, t.Effect, []string{t.Scope}))
	}
	// reverse channel — server drives client; denied unless explicitly granted.
	classify = append(classify,
		sseRule("server.sampling", "sampling/createMessage", "external", []string{"mcp:sampling"}),
		sseRule("server.elicitation", "elicitation/create", "external", []string{"mcp:elicit"}),
		sseRule("server.roots", "roots/list", "read", []string{"mcp:roots"}),
	)

	doc := map[string]any{
		"vendor":   id,
		"version":  "1.0.0",
		"classify": classify,
		"default":  map[string]any{"effect": "unknown"},
	}
	// Display-only curated semantics ride as a sibling of `classify`. The enforcement parse
	// (core.Adapter) ignores unknown keys, so this NEVER affects authority; loadConfig extracts it
	// separately for the consent render. Only tools with a non-zero Semantics are included.
	sem := map[string]introspect.ToolSemantics{}
	for _, t := range tools {
		if !IsZeroSemantics(t.Semantics) {
			sem[t.Name] = t.Semantics
		}
	}
	if len(sem) > 0 {
		doc["semantics"] = sem
	}
	// Display-only per-tool descriptions ride as another sibling of `classify`, same as semantics:
	// core.Adapter ignores unknown keys, so this NEVER affects authority. Only tools with a
	// non-empty description are included.
	descs := map[string]string{}
	for _, t := range tools {
		if t.Description != "" {
			descs[t.Name] = t.Description
		}
	}
	if len(descs) > 0 {
		doc["descriptions"] = descs
	}
	b, _ := json.Marshal(doc)
	return b
}

// SeedSemantics fills a name-heuristic default (DeriveSemantics(name,nil)) for any tool whose
// Semantics is the zero value, so the stored adapter doc is always populated. Operator-curated
// values are left untouched. Display-only — never gates authority.
func SeedSemantics(tools []ToolSpec) {
	for i := range tools {
		if IsZeroSemantics(tools[i].Semantics) {
			tools[i].Semantics = introspect.DeriveSemantics(tools[i].Name, nil)
		}
	}
}

// IsZeroSemantics reports whether a ToolSemantics is the empty value the operator sends when
// they didn't curate a tool (all fields blank, no sources). ToolSemantics carries a map, so it
// isn't comparable with ==.
func IsZeroSemantics(s introspect.ToolSemantics) bool {
	return s.Reversible == "" && s.Idempotent == "" && s.OpenWorld == "" && s.Cost == "" && len(s.Sources) == 0
}

// BuildAdvisor emits a human-facing advisor: a description + risk per scope. Intent hints are
// left empty for now (the operator can refine them); over-ask detection then simply has no
// hints to match against.
func BuildAdvisor(id, name string, tools []ToolSpec, scopes []string) json.RawMessage {
	// remember the strongest effect seen per scope, to set its risk
	effectOfScope := map[string]string{"mcp:connect": "read"}
	for _, t := range tools {
		if t.Scope == "" || IsUnknown(t.Effect) {
			continue
		}
		if Rank(t.Effect) > Rank(effectOfScope[t.Scope]) {
			effectOfScope[t.Scope] = t.Effect
		}
	}
	scopeDocs := map[string]any{}
	for _, sc := range scopes {
		eff := effectOfScope[sc]
		scopeDocs[sc] = map[string]any{"human": HumanScope(sc, eff), "risk": RiskOf(eff)}
	}
	doc := map[string]any{
		"vendor":       id,
		"display_name": name,
		"scopes":       scopeDocs,
		"intent_hints": map[string]any{},
	}
	b, _ := json.Marshal(doc)
	return b
}

// --- helpers ---

// IsUnknown reports whether an effect classification is absent or explicitly unknown.
func IsUnknown(effect string) bool { return effect == "" || effect == "unknown" }

// Rank orders effects by strength (read < write < external < destructive < spends).
func Rank(effect string) int {
	switch effect {
	case "read":
		return 1
	case "write":
		return 2
	case "external":
		return 3
	case "destructive":
		return 4
	case "spends":
		return 5
	}
	return 0
}

// RiskOf maps an effect to the coarse risk band the consent UI renders.
func RiskOf(effect string) string {
	switch effect {
	case "read":
		return "low"
	case "write":
		return "medium"
	case "external", "destructive", "spends":
		return "high"
	}
	return "medium"
}

// HumanScope renders a scope as the one-line human description advisors carry.
func HumanScope(scope, effect string) string {
	if scope == "mcp:connect" {
		return "Connect and list what the server offers"
	}
	parts := strings.SplitN(scope, ":", 2)
	subject := parts[0]
	switch effect {
	case "read":
		return "Read " + subject
	case "write", "destructive":
		return "Create, modify, and delete " + subject
	case "external":
		return "Send / reach the outside world via " + subject
	case "spends":
		return "Spend money via " + subject
	}
	return scope
}

// SortedKeys returns a set's keys sorted — the deterministic scope-list order everywhere.
func SortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Slug normalizes a target id to lowercase kebab (letters, digits, dash).
func Slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '-':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
