package main

import (
	"fmt"
	"testing"

	"delegent.dev/gateway"
)

// TestVisualSmoke renders each screen with fixture data for eyeballing via -v. Assertions
// are minimal — this exists so layout changes are LOOKED AT, not just string-matched.
func TestVisualSmoke(t *testing.T) {
	f := &fakeOps{resolveOK: true}
	f.consents = consentBundle{Live: []gateway.PendingView{{
		ID: "a1005c9c46b99bf38939ffcb3dbaff26", TargetID: "github", AgentName: "new agent c…",
		Headline: "new agent connection wants to Get details of the authenticated GitHub user",
		Intent:   "Get the authenticated user's GitHub username to list their repositories",
		Scopes:   []gateway.ScopeView{{Scope: "data:read", Human: "Read data", Risk: "low"}},
		OverAskWarnings: []string{"Requesting 'data:read', but the stated task only requires: ."},
	}}}

	r := newRootModel(f)
	r.width, r.height = 110, 30
	for i, name := range r.tabs {
		r.active = i
		r.screens[i] = drain(t, r.screens[i], r.screens[i].init())
		if name == "Alerts" {
			r.pendingAlerts = 1
			r.screens[i] = press(t, r.screens[i], "a") // open the picker for the smoke shot
		}
		fmt.Printf("\n════════ %s ════════\n%s\n", name, r.View())
	}
}
