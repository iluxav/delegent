package provision

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"delegent.dev/gateway/store"
)

// This file is the re-classification core shared by every policy-editing surface (the hosted
// console API and the local TUI): read the stored adapter back into editable tool rows, and
// rebuild adapter + advisor + entitlement from an edited row set — EXACTLY as CreateTarget
// does, so no editing path can drift from the create path.

// ValidEffect reports whether effect is one the classifier understands. Empty/"unknown" are
// accepted (they leave the tool unclassified → denied by the adapter default).
func ValidEffect(effect string) bool {
	switch effect {
	case "", "unknown", "read", "write", "destructive", "external", "spends":
		return true
	}
	return false
}

// adapterFile is the shape of the stored adapter document this package itself emits.
type adapterFile struct {
	Classify []struct {
		ID    string `json:"id"`
		Match struct {
			Method string         `json:"method"`
			Body   map[string]any `json:"body"`
		} `json:"match"`
		Effect string   `json:"effect"`
		Scopes []string `json:"scopes"`
	} `json:"classify"`
	Default struct {
		Effect string `json:"effect"`
	} `json:"default"`
	Semantics    map[string]json.RawMessage `json:"semantics"`
	Descriptions map[string]string          `json:"descriptions"`
}

// ParseAdapterTools reads a stored adapter document back into the editable tool rows
// (tools/call rules only — the handshake and reverse-channel preamble BuildAdapter always
// re-emits is not editable). The inverse of BuildAdapter for the tool section.
func ParseAdapterTools(doc json.RawMessage) ([]ToolSpec, error) {
	var af adapterFile
	if err := json.Unmarshal(doc, &af); err != nil {
		return nil, err
	}
	var out []ToolSpec
	for _, c := range af.Classify {
		name, _ := c.Match.Body["params.name"].(string)
		if c.Match.Method == "SSE" || name == "" {
			continue // preamble / reverse-channel rules, not tools
		}
		scope := ""
		if len(c.Scopes) > 0 {
			scope = c.Scopes[0]
		}
		spec := ToolSpec{Name: name, Effect: c.Effect, Scope: scope, Description: af.Descriptions[name]}
		if raw, ok := af.Semantics[name]; ok {
			_ = json.Unmarshal(raw, &spec.Semantics)
		}
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ScopeDoc is one advisor scope entry (the human line + risk band the consent UI renders).
type ScopeDoc struct {
	Scope string `json:"scope"`
	Human string `json:"human"`
	Risk  string `json:"risk"`
}

// ParseAdvisorScopes reads a stored advisor document back into its scope docs, sorted.
func ParseAdvisorScopes(doc json.RawMessage) ([]ScopeDoc, error) {
	var av struct {
		Scopes map[string]struct {
			Human string `json:"human"`
			Risk  string `json:"risk"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal(doc, &av); err != nil {
		return nil, err
	}
	out := make([]ScopeDoc, 0, len(av.Scopes))
	for sc, d := range av.Scopes {
		out = append(out, ScopeDoc{Scope: sc, Human: d.Human, Risk: d.Risk})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out, nil
}

// UpdatePolicy re-classifies a target from an edited tool-row set: rebuilds the adapter
// (enforcement rules) and advisor (scope docs) exactly as CreateTarget does, and UNIONs the
// owner's entitlement with any newly introduced scopes — never narrowing it (manual narrowing
// and Disabled opt-outs are preserved untouched). name overrides the display name when
// non-empty. Returns the full classified scope set. The caller invalidates the live gateway.
func UpdatePolicy(ctx context.Context, st store.Store, targetID, name string, tools []ToolSpec) ([]string, error) {
	t, err := st.GetTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	for _, tool := range tools {
		if tool.Name == "" {
			return nil, errors.New("each tool needs a name")
		}
		if !ValidEffect(tool.Effect) {
			return nil, errors.New("invalid effect: " + tool.Effect)
		}
	}
	SeedSemantics(tools)

	scopeSet := map[string]bool{"mcp:connect": true}
	for _, tool := range tools {
		if tool.Scope != "" && !IsUnknown(tool.Effect) {
			scopeSet[tool.Scope] = true
		}
	}
	scopes := SortedKeys(scopeSet)

	if name == "" {
		name = t.Name
	}
	if err := st.PutAdapter(ctx, &store.AdapterDoc{ID: targetID, Name: name, Doc: BuildAdapter(targetID, tools)}); err != nil {
		return nil, err
	}
	if err := st.PutAdvisor(ctx, &store.AdvisorDoc{ID: targetID, Name: name, Doc: BuildAdvisor(targetID, name, tools, scopes)}); err != nil {
		return nil, err
	}

	if t.Owner != "" {
		union := map[string]bool{}
		var disabled []string // operator opt-outs survive re-classification untouched
		if ent, err := st.GetEntitlement(ctx, t.Owner, targetID); err == nil {
			for _, sc := range ent.Scopes {
				union[sc] = true
			}
			disabled = ent.Disabled
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		for sc := range scopeSet {
			union[sc] = true
		}
		if err := st.PutEntitlement(ctx, &store.Entitlement{
			UserID: t.Owner, TargetID: targetID, Scopes: SortedKeys(union), Disabled: disabled,
		}); err != nil {
			return nil, err
		}
	}
	return scopes, nil
}
