package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// Ed25519 crypto + delegation. Signing authority is injected via Signer so core stays
// pure and the control plane can back it with KMS. Verification needs only public keys.

// Signer produces detached ed25519 signatures over arbitrary bytes and exposes the
// issuer public key (hex). A KMS-backed implementation satisfies the same interface.
type Signer interface {
	Public() string                  // issuer public key, hex (raw 32 bytes)
	Sign(msg []byte) (string, error) // detached signature, hex
}

// Clock is injected so core never reads the wall clock.
type Clock interface{ NowMillis() int64 }

// RootStore resolves a named root issuer ("root:alice") to its public key. Only named
// roots may anchor a chain; intermediate links are keyed by raw hex public keys.
type RootStore interface {
	IssuerPubKey(iss string) (string, bool)
}

// MapRootStore is a trivial in-memory RootStore.
type MapRootStore map[string]string

func (m MapRootStore) IssuerPubKey(iss string) (string, bool) { p, ok := m[iss]; return p, ok }

// Ed25519Signer is a local, in-process Signer. In production the control plane swaps
// this for a KMS-backed Signer implementing the same interface.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  string
}

func NewEd25519Signer(priv ed25519.PrivateKey) Ed25519Signer {
	return Ed25519Signer{priv: priv, pub: hex.EncodeToString(priv.Public().(ed25519.PublicKey))}
}
func (s Ed25519Signer) Public() string { return s.pub }
func (s Ed25519Signer) Sign(msg []byte) (string, error) {
	return hex.EncodeToString(ed25519.Sign(s.priv, msg)), nil
}

// NewKeypair generates a fresh ed25519 keypair; pub is the raw 32-byte key, hex.
func NewKeypair() (pub string, priv ed25519.PrivateKey, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(pk), sk, nil
}

// VerifyBytes checks a detached ed25519 signature. Malformed key/sig -> false (fail closed).
func VerifyBytes(pubHex string, msg []byte, sigHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// SignSlip signs a slip body over its canonical encoding.
func SignSlip(body SlipBody, signer Signer) (Slip, error) {
	sig, err := signer.Sign(Canonical(body))
	if err != nil {
		return Slip{}, err
	}
	return Slip{Body: body, Sig: sig}, nil
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func issuerPub(roots RootStore, iss string) (string, bool) {
	if p, ok := roots.IssuerPubKey(iss); ok {
		return p, true
	}
	if hex64.MatchString(iss) {
		return iss, true // an intermediate link keyed by its raw public key
	}
	return "", false
}

// Caveats attenuate a parent slip. A nil field means "inherit the parent" (no change);
// a set field is intersected/clamped against the parent — never widened.
type Caveats struct {
	Effects   *Effect
	Methods   *Method
	Scopes    *[]string
	Ceiling   *[]string
	Resources *[]string
	Budget    *float64
	Exp       *int64
	Depth     *int
}

// Narrow mints a strictly-weaker child slip. Offline, no authority contacted. Every
// caveat is clamped against the folded parent; widening attempts are reported, not
// hidden. The nonce is injected (core holds no randomness).
func Narrow(parent Chain, c Caveats, childPub string, parentSigner Signer, nonce string) (Chain, []string, error) {
	if len(parent) == 0 {
		return nil, nil, errors.New("empty parent chain")
	}
	var anomalies []string
	p := Fold(parent, nil)
	if p.Depth <= 0 {
		return nil, nil, errors.New("depth exhausted: parent slip allows no further sub-delegation")
	}

	// scopes: keep only those the parent holds
	scopes := p.Scopes
	if c.Scopes != nil {
		scopes = filterIn(*c.Scopes, p.Scopes)
		if len(scopes) < len(*c.Scopes) {
			anomalies = append(anomalies, "narrow() asked for scopes outside parent grant — dropped")
		}
	}

	// ceiling: what the caller asked for PLUS the child's held scopes (a structural
	// convenience so augment/re-mint never loses what is already held), intersected with the
	// parent's ceiling. Only the EXPLICIT ask can be anomalous — held scopes falling outside
	// the parent's ceiling is the normal case for a parent with no ceiling at all.
	wanted := make([]string, 0)
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			wanted = append(wanted, s)
		}
	}
	var explicit []string // the caller's deduped ceiling request
	if c.Ceiling != nil {
		for _, s := range *c.Ceiling {
			add(s)
		}
		explicit = append(explicit, wanted...)
	}
	for _, s := range scopes {
		add(s)
	}
	ceiling := filterIn(wanted, p.Ceiling)
	if len(filterIn(explicit, p.Ceiling)) < len(explicit) {
		anomalies = append(anomalies, "narrow() asked for a ceiling outside the parent's own ceiling — dropped")
	}

	// effects/methods: SET intersection
	effects := p.Effects
	if c.Effects != nil {
		effects = *c.Effects & p.Effects
		if *c.Effects&p.Effects != *c.Effects {
			anomalies = append(anomalies, fmt.Sprintf("narrow() asked for effects [%s] ⊄ parent [%s] — dropped", EffectNames(*c.Effects), EffectNames(p.Effects)))
		}
	}
	methods := p.Methods
	if c.Methods != nil {
		methods = *c.Methods & p.Methods
	}

	resources := p.Resources
	if c.Resources != nil {
		resources = foldResources(p.Resources, *c.Resources)
	}

	budget := p.Budget
	if c.Budget != nil {
		if *c.Budget > p.Budget {
			anomalies = append(anomalies, fmt.Sprintf("narrow() asked for budget %s > parent %s — clamped", jsNumber(*c.Budget), jsNumber(p.Budget)))
		}
		budget = min(*c.Budget, p.Budget)
	}
	exp := p.Exp
	if c.Exp != nil {
		if *c.Exp > p.Exp {
			anomalies = append(anomalies, fmt.Sprintf("narrow() asked for exp %d > parent %d — clamped", *c.Exp, p.Exp))
		}
		exp = min(*c.Exp, p.Exp)
	}
	depth := p.Depth - 1
	if c.Depth != nil {
		if *c.Depth > p.Depth-1 {
			anomalies = append(anomalies, fmt.Sprintf("narrow() asked for depth %d > parent %d — clamped", *c.Depth, p.Depth-1))
		}
		depth = min(*c.Depth, p.Depth-1)
	}

	body := SlipBody{
		V:         1,
		Iss:       parent[len(parent)-1].Body.Aud, // issued BY the parent holder
		Aud:       childPub,                       // BOUND to the child key
		Vendor:    p.Vendor,
		Effects:   effects,
		Methods:   methods,
		Scopes:    scopes,
		Ceiling:   ceiling,
		Resources: resources,
		Budget:    budget,
		Exp:       exp,
		Depth:     depth,
		Nonce:     nonce,
	}
	child, err := SignSlip(body, parentSigner)
	if err != nil {
		return nil, anomalies, err
	}
	return append(append(Chain{}, parent...), child), anomalies, nil
}

// VerifyResult is the outcome of VerifyChain; Effective/Anomalies valid when OK, Reason
// set when not. Reasons are specific — they ARE the audit trail.
type VerifyResult struct {
	OK        bool
	Effective SlipBody
	Anomalies []string
	Reason    string
}

func vfail(reason string) VerifyResult { return VerifyResult{OK: false, Reason: reason} }

// ReasonPossessionFailed is the exact VerifyChain refusal for a failed holder
// proof-of-possession. Exported so tooling (e.g. the CLI's structural verify, which forgives
// exactly this failure) can match it structurally instead of scraping prose.
const ReasonPossessionFailed = "proof-of-possession failed: request not signed by the bound key"

// VerifyChain checks a chain end to end, cheapest first, fail fast: trusted root, link
// continuity, every signature, caller binding, proof-of-possession, expiry, and depth.
func VerifyChain(chain Chain, callerPub, callerSig string, reqBytes []byte, roots RootStore, now int64) VerifyResult {
	if len(chain) == 0 {
		return vfail("empty chain")
	}
	// 1. root issuer is a trusted, named root
	root := chain[0].Body
	if _, ok := roots.IssuerPubKey(root.Iss); !ok {
		return vfail(fmt.Sprintf("untrusted root issuer '%s'", root.Iss))
	}
	// 2. each link is issued to the key of the next holder
	for i := 1; i < len(chain); i++ {
		if chain[i].Body.Iss != chain[i-1].Body.Aud {
			return vfail(fmt.Sprintf("broken chain at link %d: issuer is not the previous holder", i))
		}
	}
	// 3. every signature verifies over canonical(body)
	for i := range chain {
		pub, ok := issuerPub(roots, chain[i].Body.Iss)
		if !ok || !VerifyBytes(pub, Canonical(chain[i].Body), chain[i].Sig) {
			return vfail(fmt.Sprintf("bad signature on link %d", i))
		}
	}
	// 4. the caller is who the last slip was issued to
	last := chain[len(chain)-1].Body
	if last.Aud != callerPub {
		return vfail("slip is bound to a different key than the caller")
	}
	// 5. proof of possession — a stolen slip is useless without the private key
	if !VerifyBytes(callerPub, reqBytes, callerSig) {
		return vfail(ReasonPossessionFailed)
	}
	// 6. nothing expired
	var anomalies []string
	effective := Fold(chain, func(m string) { anomalies = append(anomalies, m) })
	if now >= effective.Exp {
		return vfail(fmt.Sprintf("slip expired at %d", effective.Exp))
	}
	// 7. delegation depth respected
	if len(chain)-1 > chain[0].Body.Depth {
		return vfail(fmt.Sprintf("chain length %d exceeds root depth %d", len(chain)-1, chain[0].Body.Depth))
	}
	return VerifyResult{OK: true, Effective: effective, Anomalies: anomalies}
}
