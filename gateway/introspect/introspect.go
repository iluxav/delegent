// Package introspect connects to an upstream MCP server, lists its tools, and DRAFTS a
// classification for each — a suggested effect and scope for a human to review and adjust.
//
// The draft is only ever a suggestion. A tool's self-declared annotations (readOnlyHint,
// destructiveHint) are asserted by the very server Delegent exists to constrain — a malicious
// server marks exfiltrate_everything readOnly. So we use name heuristics + those hints to seed
// a draft, but the operator signs it; anything we can't place lands as `unknown`, which is
// denied by default. The vendor publishes the interface, not the danger.
package introspect

import (
	"context"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DraftTool is one upstream tool with its suggested classification.
type DraftTool struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Effect      string        `json:"effect"` // read|write|destructive|spends|external|unknown
	Scope       string        `json:"scope"`  // e.g. "files:read"; "" when unknown
	Unknown     bool          `json:"unknown"`
	Hints       []string      `json:"hints,omitempty"` // what the server asserted (advisory only)
	Semantics   ToolSemantics `json:"semantics"`       // derived reversibility/idempotency/open-world/cost
}

// ToolSemantics is the derived, advisory-only semantic profile of a tool. Every value carries
// its provenance in Sources so callers can caveat server-asserted claims. Like DraftTool, this
// is display-only and NEVER used to widen or gate authority — the effect gate is unchanged.
type ToolSemantics struct {
	Reversible string            `json:"reversible"`        // "reversible" | "irreversible" | "unknown"
	Idempotent string            `json:"idempotent"`        // "yes" | "no" | "unknown"
	OpenWorld  string            `json:"open_world"`        // "yes" | "no" | "unknown"
	Cost       string            `json:"cost"`              // "free" | "spend" | "unknown"
	Sources    map[string]string `json:"sources,omitempty"` // field -> "annotation" | "heuristic"
}

// Result is the introspection outcome handed back for review.
type Result struct {
	Tools []DraftTool `json:"tools"`
}

// authTransport attaches the credential as a Bearer header on the introspection connection.
type authTransport struct {
	cred string
	base http.RoundTripper
}

func (a *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+a.cred)
	return a.base.RoundTrip(r)
}

// Introspect connects to a Streamable-HTTP MCP endpoint (attaching credential as a Bearer
// token if non-empty), lists its tools, and returns a drafted classification per tool.
func Introspect(ctx context.Context, endpoint, credential string) (*Result, error) {
	httpClient := &http.Client{}
	if credential != "" {
		httpClient.Transport = &authTransport{cred: credential, base: http.DefaultTransport}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "delegent-introspect", Version: "0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}, nil)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	list, err := sess.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	out := &Result{Tools: make([]DraftTool, 0, len(list.Tools))}
	for _, t := range list.Tools {
		out.Tools = append(out.Tools, draft(t))
	}
	return out, nil
}

// draft suggests an effect + scope for one tool from its name, description, and (advisory)
// annotations.
func draft(t *mcp.Tool) DraftTool {
	name := strings.ToLower(t.Name)
	cat := category(name)
	effect := effectFor(name, t.Annotations)

	d := DraftTool{Name: t.Name, Description: t.Description, Effect: effect, Semantics: deriveSemantics(t.Name, t.Annotations)}
	if t.Annotations != nil {
		if t.Annotations.ReadOnlyHint {
			d.Hints = append(d.Hints, "server: readOnly")
		}
		if t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
			d.Hints = append(d.Hints, "server: destructive")
		}
	}

	switch effect {
	case "spends":
		d.Scope = "billing:spend"
	case "external":
		if cat == "mail" {
			d.Scope = "mail:send"
		} else {
			d.Scope = cat + ":send"
		}
	case "read":
		d.Scope = cat + ":read"
	case "write", "destructive":
		d.Scope = cat + ":write"
	default:
		d.Effect = "unknown"
		d.Unknown = true
	}
	return d
}

// category guesses a resource family from the tool name; defaults to "data".
func category(name string) string {
	switch {
	case containsAny(name, "file", "doc", "note", "blob", "storage", "folder", "path"):
		return "files"
	case containsAny(name, "mail", "email"):
		return "mail"
	case containsAny(name, "pay", "purchase", "buy", "charge", "order", "invoice", "billing", "checkout"):
		return "billing"
	case containsAny(name, "message", "notify", "slack", "chat", "post", "publish", "sms", "send"):
		return "messaging"
	case containsAny(name, "calendar", "event", "meeting", "schedule"):
		return "calendar"
	case containsAny(name, "user", "account", "profile", "member"):
		return "identity"
	default:
		return "data"
	}
}

// Name-verb sets used by the draft heuristics. These are the strongest (and only
// non-adversarial) signal — the vendor names its interface even when it lies in its hints.
var (
	// readVerbs mark a tool as observe-only: reversible, idempotent, free.
	readVerbs = []string{"read", "get", "list", "search", "fetch", "view", "find", "show", "describe", "query"}
	// destroyVerbs mark an irreversible mutation for the semantic profile.
	destroyVerbs = []string{"delete", "remove", "destroy", "drop", "purge", "revoke", "wipe", "erase"}
	// createVerbs mark a non-idempotent mutation (each call adds a new thing).
	createVerbs = []string{"create", "add", "append", "send", "post", "insert", "upload"}
	// spendVerbs mark a tool that moves money.
	spendVerbs = []string{"buy", "purchase", "pay", "charge", "order", "checkout", "subscribe"}
	// openWorldVerbs mark a tool that reaches an external/untrusted system.
	openWorldVerbs = []string{"fetch", "search", "web", "browse", "crawl", "http", "url"}
)

// effectFor drafts an effect from name verbs first (strongest signal), then falls back to the
// server's advisory hints, then to unknown (fail-closed).
func effectFor(name string, ann *mcp.ToolAnnotations) string {
	switch {
	case containsAny(name, "delete", "remove", "purge", "destroy", "drop", "revoke", "cancel"):
		return "destructive"
	case containsAny(name, "buy", "purchase", "pay", "charge", "order", "checkout"):
		return "spends"
	case containsAny(name, "email", "notify", "publish", "sms"):
		return "external"
	case containsAny(name, "send", "post", "message"):
		return "external"
	case containsAny(name, "write", "create", "update", "save", "edit", "put", "set", "upload", "modify", "add", "insert"):
		return "write"
	case containsAny(name, readVerbs...):
		return "read"
	}
	// no verb matched — lean on the (advisory) annotations, else unknown
	if ann != nil {
		if ann.DestructiveHint != nil && *ann.DestructiveHint {
			return "destructive"
		}
		if ann.ReadOnlyHint {
			return "read"
		}
	}
	return "unknown"
}

// DeriveSemantics is the exported entry point to deriveSemantics for callers in other packages
// (the gateway computes it at the mirror loop). Display-only, same contract as deriveSemantics.
func DeriveSemantics(name string, ann *mcp.ToolAnnotations) ToolSemantics {
	return deriveSemantics(name, ann)
}

// deriveSemantics builds the advisory semantic profile for a tool. Pure, no I/O — mirrors
// effectFor. Per the trust model (annotations are server-asserted and adversarial), name
// heuristics lead for reversibility; annotations only corroborate or fill gaps. Every non-unknown
// value records its provenance in Sources. Display-only: never used to gate authority.
func deriveSemantics(name string, ann *mcp.ToolAnnotations) ToolSemantics {
	name = strings.ToLower(name)
	sem := ToolSemantics{
		Reversible: "unknown",
		Idempotent: "unknown",
		OpenWorld:  "unknown",
		Cost:       "unknown",
		Sources:    map[string]string{},
	}

	readVerb := containsAny(name, readVerbs...)
	readOnly := readVerb || (ann != nil && ann.ReadOnlyHint)

	// Reversible — heuristic (name) first, then annotation.
	switch {
	case containsAny(name, destroyVerbs...):
		sem.Reversible, sem.Sources["reversible"] = "irreversible", "heuristic"
	case ann != nil && ann.DestructiveHint != nil && *ann.DestructiveHint:
		sem.Reversible, sem.Sources["reversible"] = "irreversible", "annotation"
	case ann != nil && ann.ReadOnlyHint:
		sem.Reversible, sem.Sources["reversible"] = "reversible", "annotation"
	case readVerb:
		sem.Reversible, sem.Sources["reversible"] = "reversible", "heuristic"
	}

	// Idempotent.
	switch {
	case ann != nil && ann.IdempotentHint:
		sem.Idempotent, sem.Sources["idempotent"] = "yes", "annotation"
	case readVerb:
		sem.Idempotent, sem.Sources["idempotent"] = "yes", "heuristic"
	case containsAny(name, createVerbs...):
		sem.Idempotent, sem.Sources["idempotent"] = "no", "heuristic"
	}

	// OpenWorld — annotation is authoritative when present, else name heuristic.
	switch {
	case ann != nil && ann.OpenWorldHint != nil:
		if *ann.OpenWorldHint {
			sem.OpenWorld = "yes"
		} else {
			sem.OpenWorld = "no"
		}
		sem.Sources["open_world"] = "annotation"
	case containsAny(name, openWorldVerbs...):
		sem.OpenWorld, sem.Sources["open_world"] = "yes", "heuristic"
	}

	// Cost.
	switch {
	case containsAny(name, spendVerbs...):
		sem.Cost, sem.Sources["cost"] = "spend", "heuristic"
	case readOnly:
		sem.Cost, sem.Sources["cost"] = "free", "heuristic"
	}

	if len(sem.Sources) == 0 {
		sem.Sources = nil
	}
	return sem
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
