package protocol

import (
	"strings"
	"testing"
)

// The ceiling anomaly must reflect what the CALLER asked for, not the structural
// convenience of folding the child's held scopes into its ceiling. A parent with no
// ceiling and a caller who requested none is perfectly normal — no anomaly.

func narrowFixture(t *testing.T, parentCeiling []string) (Chain, Signer, string) {
	t.Helper()
	rootPub, rootPriv, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = rootPub
	holderPub, holderPriv, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	childPub, _, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	slip, err := SignSlip(SlipBody{
		V: 1, Iss: "root:alice", Aud: holderPub, Vendor: "gh",
		Effects: EffectRead, Scopes: []string{"repos:read"}, Ceiling: parentCeiling,
		Exp: 9_000_000_000_000, Depth: 2, Nonce: "n1",
	}, NewEd25519Signer(rootPriv))
	if err != nil {
		t.Fatal(err)
	}
	return Chain{slip}, NewEd25519Signer(holderPriv), childPub
}

func TestNarrowNoCeilingAskNoAnomaly(t *testing.T) {
	parent, holder, childPub := narrowFixture(t, nil) // parent has NO ceiling
	_, anomalies, err := Narrow(parent, Caveats{}, childPub, holder, "n2")
	if err != nil {
		t.Fatalf("narrow: %v", err)
	}
	for _, a := range anomalies {
		if strings.Contains(a, "ceiling") {
			t.Fatalf("spurious ceiling anomaly with no ceiling requested: %q", a)
		}
	}
}

func TestNarrowExplicitCeilingOverAskStillFlagged(t *testing.T) {
	parent, holder, childPub := narrowFixture(t, []string{"repos:read"})
	ask := []string{"repos:read", "repos:admin"} // repos:admin exceeds the parent ceiling
	_, anomalies, err := Narrow(parent, Caveats{Ceiling: &ask}, childPub, holder, "n2")
	if err != nil {
		t.Fatalf("narrow: %v", err)
	}
	found := false
	for _, a := range anomalies {
		if strings.Contains(a, "ceiling") {
			found = true
		}
	}
	if !found {
		t.Fatalf("explicit ceiling over-ask must be flagged; anomalies: %v", anomalies)
	}
}

func TestNarrowExplicitCeilingWithinParentNoAnomaly(t *testing.T) {
	parent, holder, childPub := narrowFixture(t, []string{"repos:read", "repos:write"})
	ask := []string{"repos:write"}
	chain, anomalies, err := Narrow(parent, Caveats{Ceiling: &ask}, childPub, holder, "n2")
	if err != nil {
		t.Fatalf("narrow: %v", err)
	}
	for _, a := range anomalies {
		if strings.Contains(a, "ceiling") {
			t.Fatalf("in-bounds ceiling ask flagged: %q", a)
		}
	}
	// the granted ceiling still contains the ask (held scopes may fold in too)
	child := chain[len(chain)-1].Body
	if !contains(child.Ceiling, "repos:write") {
		t.Fatalf("child ceiling lost the granted ask: %v", child.Ceiling)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
