// Package loader reads adapter/advisor/principals JSON off disk into typed values. In
// the product these bundles are signed and distributed by the control plane; for now
// they are read from the adapters/ directory.
package loader

import (
	"encoding/json"
	"os"

	core "delegent.dev/protocol"
)

// Adapter reads and parses an adapter.json into a core.Adapter (the classification policy).
func Adapter(path string) (core.Adapter, error) {
	var a core.Adapter
	return a, readJSON(path, &a)
}

// ScopeInfo is the human-facing description of one scope (advisor.json).
type ScopeInfo struct {
	Human    string   `json:"human"`
	Risk     string   `json:"risk"`
	Warnings []string `json:"warnings"`
}

// Advisor is the human-facing policy: scope descriptions and intent→scope hints. It is
// separate from the adapter because it has a different blast radius (advisory, not enforcing).
type Advisor struct {
	Vendor      string               `json:"vendor"`
	DisplayName string               `json:"display_name"`
	Scopes      map[string]ScopeInfo `json:"scopes"`
	IntentHints map[string][]string  `json:"intent_hints"`
}

func LoadAdvisor(path string) (Advisor, error) {
	var a Advisor
	return a, readJSON(path, &a)
}

// Principals maps each principal to the scopes it is ENTITLED to — the top of the chain.
type Principals struct {
	Vendor     string              `json:"vendor"`
	Principals map[string][]string `json:"principals"`
}

func LoadPrincipals(path string) (Principals, error) {
	var p Principals
	return p, readJSON(path, &p)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
