package protocol

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestCrossLanguageVerify proves the point of the whole port: a slip chain MINTED AND
// SIGNED IN TYPESCRIPT verifies in Go, including a narrowed child. This only passes if
// canonical serialization is byte-identical across the two implementations.
func TestCrossLanguageVerify(t *testing.T) {
	data, err := os.ReadFile("testdata/crypto_vectors.jsonl")
	if err != nil {
		t.Fatalf("read crypto vectors: %v", err)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var v struct {
			Label     string          `json:"label"`
			Chain     Chain           `json:"chain"`
			CallerPub string          `json:"callerPub"`
			CallerSig string          `json:"callerSig"`
			ReqObj    json.RawMessage `json:"reqObj"`
			RootPub   string          `json:"rootPub"`
			Now       int64           `json:"now"`
			WantOK    bool            `json:"wantOK"`
			WantEff   uint            `json:"wantEffects"`
		}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		var reqObj any
		if err := json.Unmarshal(v.ReqObj, &reqObj); err != nil {
			t.Fatalf("vector %d reqObj: %v", i, err)
		}
		reqBytes := Canonical(reqObj) // Go's canonical must equal the TS bytes the caller signed
		roots := MapRootStore{"root:alice": v.RootPub}

		res := VerifyChain(v.Chain, v.CallerPub, v.CallerSig, reqBytes, roots, v.Now)
		if res.OK != v.WantOK {
			t.Fatalf("[%s] verify OK=%v want %v (reason: %s)", v.Label, res.OK, v.WantOK, res.Reason)
		}
		if res.OK && res.Effective.Effects != Effect(v.WantEff) {
			t.Errorf("[%s] effective effects = %s, want %s", v.Label, EffectNames(res.Effective.Effects), EffectNames(Effect(v.WantEff)))
		}
	}
}

// TestVerifyChainNegatives confirms the guards fail closed on tampering.
func TestVerifyChainNegatives(t *testing.T) {
	data, _ := os.ReadFile("testdata/crypto_vectors.jsonl")
	line := strings.Split(strings.TrimSpace(string(data)), "\n")[0]
	var v struct {
		Chain     Chain           `json:"chain"`
		CallerPub string          `json:"callerPub"`
		CallerSig string          `json:"callerSig"`
		ReqObj    json.RawMessage `json:"reqObj"`
		RootPub   string          `json:"rootPub"`
		Now       int64           `json:"now"`
	}
	_ = json.Unmarshal([]byte(line), &v)
	var reqObj any
	_ = json.Unmarshal(v.ReqObj, &reqObj)
	reqBytes := Canonical(reqObj)
	roots := MapRootStore{"root:alice": v.RootPub}

	base := VerifyChain(v.Chain, v.CallerPub, v.CallerSig, reqBytes, roots, v.Now)
	if !base.OK {
		t.Fatalf("baseline should verify: %s", base.Reason)
	}

	// Untrusted root.
	if r := VerifyChain(v.Chain, v.CallerPub, v.CallerSig, reqBytes, MapRootStore{}, v.Now); r.OK {
		t.Error("expected deny for untrusted root")
	}
	// Tampered request bytes -> proof-of-possession fails.
	if r := VerifyChain(v.Chain, v.CallerPub, v.CallerSig, []byte("different"), roots, v.Now); r.OK {
		t.Error("expected deny for tampered request bytes")
	}
	// Wrong caller key.
	if r := VerifyChain(v.Chain, "00"+v.CallerPub[2:], v.CallerSig, reqBytes, roots, v.Now); r.OK {
		t.Error("expected deny for wrong caller key")
	}
	// Expired.
	if r := VerifyChain(v.Chain, v.CallerPub, v.CallerSig, reqBytes, roots, 1<<62); r.OK {
		t.Error("expected deny for expired slip")
	}
	// Widening a body bit doesn't help: mutate an effect then re-verify -> bad signature.
	tampered := append(Chain{}, v.Chain...)
	tampered[0].Body.Effects = EffectRead | EffectWrite | EffectDestructive
	if r := VerifyChain(tampered, v.CallerPub, v.CallerSig, reqBytes, roots, v.Now); r.OK {
		t.Error("expected deny after mutating a signed body field")
	}
}

// TestNativeRoundTrip: Go can mint, narrow, and verify its own chains.
func TestNativeRoundTrip(t *testing.T) {
	rootPub, rootPriv, _ := NewKeypair()
	agentPub, agentPriv, _ := NewKeypair()
	childPub, _, _ := NewKeypair()
	rootSigner := NewEd25519Signer(rootPriv)
	agentSigner := NewEd25519Signer(agentPriv)
	roots := MapRootStore{"root:alice": rootPub}

	rootBody := SlipBody{
		V: 1, Iss: "root:alice", Aud: agentPub, Vendor: "mcp-remote",
		Effects: EffectRead | EffectWrite, Methods: MethodPOST,
		Scopes: []string{"mcp:connect", "files:read", "files:write"}, Ceiling: []string{"mcp:connect", "files:read", "files:write"},
		Resources: []string{""}, Budget: 10, Exp: 1 << 40, Depth: 2, Nonce: "seed1",
	}
	rootSlip, err := SignSlip(rootBody, rootSigner)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{rootSlip}

	// The agent signs a request and its own chain verifies.
	reqBytes := Canonical(map[string]any{"action": "POST", "resource": "/mcp"})
	sig, _ := agentSigner.Sign(reqBytes)
	if r := VerifyChain(chain, agentPub, sig, reqBytes, roots, 1000); !r.OK {
		t.Fatalf("native root chain should verify: %s", r.Reason)
	}

	rd := EffectRead
	sc := []string{"mcp:connect", "files:read"}
	childChain, anomalies, err := Narrow(chain, Caveats{Effects: &rd, Scopes: &sc}, childPub, agentSigner, "seed2")
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 0 {
		t.Errorf("unexpected anomalies: %v", anomalies)
	}
	eff := Fold(childChain, nil)
	if eff.Effects != EffectRead {
		t.Errorf("child effects = %s, want read", EffectNames(eff.Effects))
	}

	// A widening narrow is a no-op that reports the attempt.
	wide := EffectRead | EffectDestructive
	_, anomalies, err = Narrow(chain, Caveats{Effects: &wide}, childPub, agentSigner, "seed3")
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) == 0 {
		t.Error("expected a widening anomaly when asking for destructive the parent lacks")
	}
}
