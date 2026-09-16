package provision_test

import (
	"encoding/json"
	"testing"

	"delegent.dev/gateway/provision"
)

// TestRefusedToolsSurvive covers the failure this was written for: a tool the classifier could
// not place got NO adapter rule, which refuses it correctly at call time but also made it
// invisible to every policy editor — so nobody could fix it. It must round-trip as unknown.
func TestRefusedToolsSurvive(t *testing.T) {
	tools := []provision.ToolSpec{
		{Name: "read-page", Effect: "read", Scope: "data:read", Description: "Read a page."},
		{Name: "move-pages", Effect: "unknown", Description: "Move pages around."},
		{Name: "no-description", Effect: "unknown"},
	}
	doc := provision.BuildAdapter("notion", tools)

	back, err := provision.ParseAdapterTools(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]provision.ToolSpec{}
	for _, s := range back {
		got[s.Name] = s
	}
	if len(got) != 3 {
		t.Fatalf("all three tools should come back, got %d: %v", len(got), got)
	}
	if got["read-page"].Effect != "read" || got["read-page"].Scope != "data:read" {
		t.Errorf("classified tool changed: %+v", got["read-page"])
	}
	for _, name := range []string{"move-pages", "no-description"} {
		if e := got[name].Effect; e != "unknown" {
			t.Errorf("%s should come back unknown, got %q", name, e)
		}
		if got[name].Scope != "" {
			t.Errorf("%s must carry no scope", name)
		}
	}

	// It is still REFUSED: no rule was emitted for it, so it falls through to the adapter's
	// unknown default rather than matching something that could be granted.
	var parsed struct {
		Classify []struct {
			Match struct {
				Body map[string]any `json:"body"`
			} `json:"match"`
		} `json:"classify"`
		Default struct {
			Effect string `json:"effect"`
		} `json:"default"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, c := range parsed.Classify {
		if c.Match.Body["params.name"] == "move-pages" {
			t.Fatal("a refused tool must not get a classify rule — that would make it grantable")
		}
	}
	if parsed.Default.Effect != "unknown" {
		t.Fatalf("default must stay unknown, got %q", parsed.Default.Effect)
	}

	// classifying it later produces a real rule, and it stops being listed as refused
	fixed := []provision.ToolSpec{
		{Name: "read-page", Effect: "read", Scope: "data:read"},
		{Name: "move-pages", Effect: "write", Scope: "pages:write"},
	}
	back, err = provision.ParseAdapterTools(provision.BuildAdapter("notion", fixed))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range back {
		if s.Name == "move-pages" && (s.Effect != "write" || s.Scope != "pages:write") {
			t.Fatalf("classifying should stick: %+v", s)
		}
	}
}
