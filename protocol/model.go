// Package protocol is the Delegent authorization algebra: the effect/method lattice,
// body-aware classification, the subset authorization test, slip minting/narrowing,
// and chain verification. It is PURE — no database, no HTTP, no wall clock, no
// randomness. Side effects are injected (Clock, Signer, RootStore) so both the
// control plane and the proxy can share one decision function with zero drift.
//
// Ported 1:1 from the TypeScript reference in src/. Behaviour is pinned by the
// conformance vectors in core/testdata, generated from the TS test suite.
package protocol

import "strconv"

// Effect is a bitmask SET (a child effect set folds with the parent by AND).
// Danger is not a line: "may notify humans" and "may irreversibly destroy" are
// independent axes, so a single ≤ ceiling cannot express "may comment, may not
// delete". As a set it can. UNKNOWN is a bit no slip may ever hold, so an
// unclassified action is denied structurally rather than by a numeric accident.
type Effect uint

const (
	EffectRead        Effect = 1  // observes state
	EffectWrite       Effect = 2  // changes state, reversibly
	EffectDestructive Effect = 4  // changes state, irreversibly
	EffectSpends      Effect = 8  // costs the principal money
	EffectExternal    Effect = 16 // affects the outside world (email, public post)
	EffectUnknown     Effect = 32 // unclassified — NO slip may ever hold this bit
)

// effectOrder mirrors the TS EFFECT declaration order so EffectNames renders
// identically ("read+destructive", never "destructive+read").
var effectOrder = []struct {
	name string
	bit  Effect
}{
	{"read", EffectRead}, {"write", EffectWrite}, {"destructive", EffectDestructive},
	{"spends", EffectSpends}, {"external", EffectExternal}, {"unknown", EffectUnknown},
}

// EffectNames renders a mask as its member names joined by '+': 5 -> "read+destructive".
// The empty set renders "nothing". This is what Alice reads, so it is the SET, not a ceiling.
func EffectNames(mask Effect) string {
	out := ""
	for _, e := range effectOrder {
		if mask&e.bit == e.bit {
			if out != "" {
				out += "+"
			}
			out += e.name
		}
	}
	if out == "" {
		return "nothing"
	}
	return out
}

// EffectByName maps a lowercase effect name to its bit. Unknown name -> (0, false),
// which callers treat as fail-closed (the UNKNOWN bit).
func EffectByName(name string) (Effect, bool) {
	for _, e := range effectOrder {
		if e.name == name {
			return e.bit, true
		}
	}
	return 0, false
}

// Method is a bitmask SET, same lattice discipline as Effect — never a ranked scale.
type Method uint

const (
	MethodGET    Method = 1
	MethodPOST   Method = 2
	MethodPUT    Method = 4
	MethodPATCH  Method = 8
	MethodDELETE Method = 16
)

var methodNames = map[Method]string{
	MethodGET: "GET", MethodPOST: "POST", MethodPUT: "PUT",
	MethodPATCH: "PATCH", MethodDELETE: "DELETE",
}

// MethodByName maps an HTTP method name to its bit. Unknown -> (0, false).
func MethodByName(name string) (Method, bool) {
	for bit, n := range methodNames {
		if n == name {
			return bit, true
		}
	}
	return 0, false
}

// MethodName renders a single method bit as its name, or "method:N" if not a known bit.
func MethodName(bit Method) string {
	if n, ok := methodNames[bit]; ok {
		return n
	}
	return "method:" + strconv.FormatUint(uint64(bit), 10)
}

// SlipBody is a signed statement of limits, bound to one agent's public key. It is
// NOT a credential. The json tags are load-bearing: Canonical signs over these exact
// keys, so they must match the TS field names byte-for-byte.
type SlipBody struct {
	V         int      `json:"v"`
	Iss       string   `json:"iss"`    // issuer public key (hex) or a root name ("root:alice")
	Aud       string   `json:"aud"`    // BOUND to this agent's public key (hex)
	Vendor    string   `json:"vendor"` //
	Effects   Effect   `json:"effects"`
	Methods   Method   `json:"methods"`
	Scopes    []string `json:"scopes"`
	Ceiling   []string `json:"ceiling"` // scopes the holder may pull later without per-request approval
	Resources []string `json:"resources"`
	Budget    float64  `json:"budget"` // USD
	Exp       int64    `json:"exp"`    // unix ms
	Depth     int      `json:"depth"`  // remaining sub-delegations
	Nonce     string   `json:"nonce"`
}

// Slip is a SlipBody plus its issuer's signature over Canonical(body).
type Slip struct {
	Body SlipBody `json:"body"`
	Sig  string   `json:"sig"` // ed25519(issuer_priv, canonical(body)), hex
}

// Chain is a slip plus all its ancestors, root first. It travels together.
type Chain []Slip

// Decision is the result of Authorize. Reason is set only when Allow is false, and
// IS the audit trail — it must name the specific thing that was refused.
type Decision struct {
	Allow  bool
	Reason string
}

func allow() Decision             { return Decision{Allow: true} }
func deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }
