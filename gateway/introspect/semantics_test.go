package introspect

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func ptrBool(b bool) *bool { return &b }

func TestDeriveSemantics(t *testing.T) {
	cases := []struct {
		desc string
		name string
		ann  *mcp.ToolAnnotations
		want ToolSemantics
	}{
		{
			// Destructive verb in name → irreversible by heuristic (trust-model: name first).
			// No read verb / readOnly / spend verb → idempotent & cost unknown.
			desc: "delete_repo/no-ann",
			name: "delete_repo",
			ann:  nil,
			want: ToolSemantics{
				Reversible: "irreversible",
				Idempotent: "unknown",
				OpenWorld:  "unknown",
				Cost:       "unknown",
				Sources:    map[string]string{"reversible": "heuristic"},
			},
		},
		{
			// ReadOnlyHint drives reversible + free; read verb drives idempotent.
			// reversible source is "annotation" (ReadOnlyHint), idempotent "heuristic" (verb, no IdempotentHint).
			desc: "list_repos/readOnly",
			name: "list_repos",
			ann:  &mcp.ToolAnnotations{ReadOnlyHint: true},
			want: ToolSemantics{
				Reversible: "reversible",
				Idempotent: "yes",
				OpenWorld:  "unknown",
				Cost:       "free",
				Sources: map[string]string{
					"reversible": "annotation",
					"idempotent": "heuristic",
					"cost":       "heuristic",
				},
			},
		},
		{
			// Spend verb → cost=spend. No other signals.
			desc: "buy_domain/no-ann",
			name: "buy_domain",
			ann:  nil,
			want: ToolSemantics{
				Reversible: "unknown",
				Idempotent: "unknown",
				OpenWorld:  "unknown",
				Cost:       "spend",
				Sources:    map[string]string{"cost": "heuristic"},
			},
		},
		{
			// OpenWorldHint set true → open_world=yes from annotation. Name also has fetch (heuristic)
			// but annotation is authoritative here and recorded as such.
			desc: "web_fetch/openWorld",
			name: "web_fetch",
			ann:  &mcp.ToolAnnotations{OpenWorldHint: ptrBool(true)},
			want: ToolSemantics{
				// "fetch" is a read verb → reversible + idempotent + free heuristics.
				Reversible: "reversible",
				Idempotent: "yes",
				OpenWorld:  "yes",
				Cost:       "free",
				Sources: map[string]string{
					"reversible": "heuristic",
					"idempotent": "heuristic",
					"open_world": "annotation",
					"cost":       "heuristic",
				},
			},
		},
		{
			// Create verb → idempotent=no (heuristic). No destructive/read verb → reversible unknown.
			desc: "create_issue/no-ann",
			name: "create_issue",
			ann:  nil,
			want: ToolSemantics{
				Reversible: "unknown",
				Idempotent: "no",
				OpenWorld:  "unknown",
				Cost:       "unknown",
				Sources:    map[string]string{"idempotent": "heuristic"},
			},
		},
		{
			// CONTRADICTION: read-y name "get_status" but server asserts DestructiveHint=true.
			// Resolved behavior per the rule list: the destructive-VERB check is on the NAME only
			// (get_status has no destructive verb), so it falls through to the DestructiveHint
			// annotation → irreversible, source "annotation". The read verb "get" does NOT get to
			// mark it reversible because the DestructiveHint branch is evaluated first.
			// This is deterministic and documented; the annotation is advisory/display-only.
			desc: "get_status/destructive-annotation-contradiction",
			name: "get_status",
			ann:  &mcp.ToolAnnotations{DestructiveHint: ptrBool(true)},
			want: ToolSemantics{
				Reversible: "irreversible",
				Idempotent: "yes", // "get" is a read verb (no IdempotentHint) → heuristic
				OpenWorld:  "unknown",
				Cost:       "free", // read verb → free
				Sources: map[string]string{
					"reversible": "annotation",
					"idempotent": "heuristic",
					"cost":       "heuristic",
				},
			},
		},
		{
			// IdempotentHint set → source annotation even though "update" isn't a read verb.
			desc: "update_config/idempotentHint",
			name: "update_config",
			ann:  &mcp.ToolAnnotations{IdempotentHint: true},
			want: ToolSemantics{
				Reversible: "unknown",
				Idempotent: "yes",
				OpenWorld:  "unknown",
				Cost:       "unknown",
				Sources:    map[string]string{"idempotent": "annotation"},
			},
		},
		{
			// OpenWorldHint false → open_world=no (annotation), overriding any name heuristic.
			desc: "search_web/openWorld-false",
			name: "search_web",
			ann:  &mcp.ToolAnnotations{OpenWorldHint: ptrBool(false)},
			want: ToolSemantics{
				Reversible: "reversible",
				Idempotent: "yes",
				OpenWorld:  "no",
				Cost:       "free",
				Sources: map[string]string{
					"reversible": "heuristic",
					"idempotent": "heuristic",
					"open_world": "annotation",
					"cost":       "heuristic",
				},
			},
		},
	}

	for _, c := range cases {
		got := deriveSemantics(c.name, c.ann)
		if got.Reversible != c.want.Reversible ||
			got.Idempotent != c.want.Idempotent ||
			got.OpenWorld != c.want.OpenWorld ||
			got.Cost != c.want.Cost {
			t.Errorf("%s: got {rev=%q idem=%q open=%q cost=%q}; want {rev=%q idem=%q open=%q cost=%q}",
				c.desc, got.Reversible, got.Idempotent, got.OpenWorld, got.Cost,
				c.want.Reversible, c.want.Idempotent, c.want.OpenWorld, c.want.Cost)
		}
		if !sourcesEqual(got.Sources, c.want.Sources) {
			t.Errorf("%s: got sources=%v; want sources=%v", c.desc, got.Sources, c.want.Sources)
		}
	}
}

func sourcesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestDraft_PopulatesSemantics(t *testing.T) {
	d := draft(&mcp.Tool{Name: "delete_repo"})
	if d.Semantics.Reversible != "irreversible" {
		t.Fatalf("draft should populate Semantics; got reversible=%q", d.Semantics.Reversible)
	}
	if d.Semantics.Sources["reversible"] != "heuristic" {
		t.Fatalf("draft Semantics should carry provenance; got sources=%v", d.Semantics.Sources)
	}
}
