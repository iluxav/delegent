// Command delegent-proto is the Delegent protocol in a terminal: mint, attenuate, inspect, and
// verify capability slips (chains), and hash/sign/verify tamper-evident receipt chains. It is
// deliberately stdlib-only — the same guarantee as the library: any party can hold the whole
// protocol with zero dependencies.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	core "delegent.dev/protocol"
)

// version is stamped via -ldflags "-X main.version=…"; "dev" for plain go build/install.
var version = "dev"

const usage = `usage: delegent-proto <command> [flags]

commands:
  keygen                       generate an ed25519 keypair (hex)
  mint                         mint and sign a root slip (a one-link chain)
  attenuate                    extend a chain with a strictly-weaker child slip
  inspect                      show a chain link by link, plus its folded limits
  verify                       verify a chain (--priv = full holder proof-of-possession;
                               without it, the auditor's structural verification)
  hash-receipts                (re)compute a receipt chain's hash linkage; --priv also signs
  verify-receipts              verify a receipt chain's integrity, order, and authenticity
  version                      print the CLI version

Run 'delegent-proto <command> -h' for that command's flags. Exit codes: 0 verified/ok,
1 refused or failed (reason on stderr), 2 usage error.`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, "delegent-proto", version)
		return 0
	case "keygen":
		err = cmdKeygen(stdout)
	case "mint":
		err = cmdMint(args[1:], stdout, stderr)
	case "attenuate":
		err = cmdAttenuate(args[1:], stdout, stderr)
	case "inspect":
		err = cmdInspect(args[1:], stdout, stderr)
	case "verify":
		err = cmdVerify(args[1:], stdout, stderr)
	case "hash-receipts":
		err = cmdHashReceipts(args[1:], stdout, stderr)
	case "verify-receipts":
		err = cmdVerifyReceipts(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "delegent-proto: unknown command %q\n%s\n", args[0], usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "delegent-proto:", err)
		return 1
	}
	return 0
}

// newFlagSet builds a flag set whose usage/errors go to the INJECTED stderr, never os.Stderr.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func cmdKeygen(stdout io.Writer) error {
	pub, priv, err := core.NewKeypair()
	if err != nil {
		return err
	}
	return writeJSON(stdout, map[string]string{"pub": pub, "priv": hex.EncodeToString(priv)})
}

var hexPub = regexp.MustCompile(`^[0-9a-f]{64}$`)

func parsePub(name, v string) (string, error) {
	v = strings.TrimSpace(v)
	if !hexPub.MatchString(v) {
		return "", fmt.Errorf("--%s must be a 64-char hex ed25519 public key, got %q", name, v)
	}
	return v, nil
}

func parsePriv(hexPriv string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexPriv))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("--priv must be a %d-byte hex ed25519 private key", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func parseEffects(csv string) (core.Effect, error) {
	var mask core.Effect
	if csv == "" {
		return 0, nil
	}
	for _, n := range strings.Split(csv, ",") {
		e, ok := core.EffectByName(strings.TrimSpace(n))
		if !ok {
			return 0, fmt.Errorf("unknown effect %q", n)
		}
		mask |= e
	}
	return mask, nil
}

var allMethods = []core.Method{core.MethodGET, core.MethodPOST, core.MethodPUT, core.MethodPATCH, core.MethodDELETE}

func parseMethods(csv string) (core.Method, error) {
	var mask core.Method
	if csv == "" {
		return 0, nil
	}
	for _, n := range strings.Split(csv, ",") {
		m, ok := core.MethodByName(strings.ToUpper(strings.TrimSpace(n)))
		if !ok {
			return 0, fmt.Errorf("unknown method %q (GET,POST,PUT,PATCH,DELETE)", n)
		}
		mask |= m
	}
	return mask, nil
}

func methodNames(mask core.Method) string {
	var out []string
	for _, m := range allMethods {
		if mask&m != 0 {
			out = append(out, core.MethodName(m))
		}
	}
	return strings.Join(out, "+")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nowMillis(flagged int64) int64 {
	if flagged != 0 {
		return flagged
	}
	return time.Now().UnixMilli()
}

func cmdMint(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("mint", stderr)
	priv := fs.String("priv", "", "issuer's ed25519 private key (hex)")
	iss := fs.String("iss", "", "issuer name, e.g. root:alice")
	aud := fs.String("aud", "", "holder public key (hex) the slip is bound to")
	vendor := fs.String("vendor", "", "vendor / target this slip applies to")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	ceiling := fs.String("ceiling", "", "comma-separated ceiling scopes (pullable later without re-consent)")
	effects := fs.String("effects", "", "comma-separated effects (read,write,destructive,external,spends)")
	methods := fs.String("methods", "", "comma-separated HTTP methods (GET,POST,PUT,PATCH,DELETE)")
	resources := fs.String("resources", "", "comma-separated resource patterns")
	budget := fs.Float64("budget", 0, "spend ceiling in USD")
	ttl := fs.Int("ttl-minutes", 60, "slip lifetime in minutes")
	depth := fs.Int("depth", 0, "remaining sub-delegations allowed")
	now := fs.Int64("now", 0, "clock override, unix ms (default: wall clock)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *priv == "" || *iss == "" || *aud == "" {
		return fmt.Errorf("mint needs --priv, --iss, and --aud")
	}
	key, err := parsePriv(*priv)
	if err != nil {
		return err
	}
	audPub, err := parsePub("aud", *aud)
	if err != nil {
		return err
	}
	eff, err := parseEffects(*effects)
	if err != nil {
		return err
	}
	meth, err := parseMethods(*methods)
	if err != nil {
		return err
	}
	body := core.SlipBody{
		V: 1, Iss: *iss, Aud: audPub, Vendor: *vendor,
		Effects: eff, Methods: meth,
		Scopes: splitCSV(*scopes), Ceiling: splitCSV(*ceiling), Resources: splitCSV(*resources),
		Budget: *budget, Exp: nowMillis(*now) + int64(*ttl)*60_000, Depth: *depth,
		Nonce: nonce(),
	}
	slip, err := core.SignSlip(body, core.NewEd25519Signer(key))
	if err != nil {
		return err
	}
	return writeJSON(stdout, core.Chain{slip})
}

func loadChain(flagName, path string) (core.Chain, error) {
	if path == "" {
		return nil, fmt.Errorf("--%s is required", flagName)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c core.Chain
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse chain %s: %w", path, err)
	}
	return c, nil
}

func cmdAttenuate(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("attenuate", stderr)
	chainPath := fs.String("chain", "", "parent chain JSON file")
	priv := fs.String("priv", "", "PARENT holder's private key (hex) — signs the child link")
	aud := fs.String("aud", "", "child holder public key (hex)")
	scopes := fs.String("scopes", "", "narrowed scopes (omit = inherit)")
	ceiling := fs.String("ceiling", "", "child's ceiling ask — clamped to the parent's ceiling (omit = held scopes only)")
	effects := fs.String("effects", "", "narrowed effects (omit = inherit)")
	methods := fs.String("methods", "", "narrowed HTTP methods (omit = inherit)")
	resources := fs.String("resources", "", "narrowed resource patterns (omit = inherit)")
	budget := fs.Float64("budget", -1, "narrowed budget USD (omit = inherit)")
	ttl := fs.Int("ttl-minutes", 0, "narrowed lifetime from now (omit = inherit)")
	depth := fs.Int("depth", -1, "child's remaining sub-delegations (omit = parent-1)")
	now := fs.Int64("now", 0, "clock override, unix ms")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainPath == "" || *priv == "" || *aud == "" {
		return fmt.Errorf("attenuate needs --chain, --priv, and --aud")
	}
	parent, err := loadChain("chain", *chainPath)
	if err != nil {
		return err
	}
	key, err := parsePriv(*priv)
	if err != nil {
		return err
	}
	audPub, err := parsePub("aud", *aud)
	if err != nil {
		return err
	}
	var cav core.Caveats
	if *scopes != "" {
		s := splitCSV(*scopes)
		cav.Scopes = &s
	}
	if *ceiling != "" {
		c := splitCSV(*ceiling)
		cav.Ceiling = &c
	}
	if *effects != "" {
		e, err := parseEffects(*effects)
		if err != nil {
			return err
		}
		cav.Effects = &e
	}
	if *methods != "" {
		m, err := parseMethods(*methods)
		if err != nil {
			return err
		}
		cav.Methods = &m
	}
	if *resources != "" {
		r := splitCSV(*resources)
		cav.Resources = &r
	}
	if *budget >= 0 {
		cav.Budget = budget
	}
	if *ttl > 0 {
		exp := nowMillis(*now) + int64(*ttl)*60_000
		cav.Exp = &exp
	}
	if *depth >= 0 {
		cav.Depth = depth
	}
	child, anomalies, err := core.Narrow(parent, cav, audPub, core.NewEd25519Signer(key), nonce())
	if err != nil {
		return err
	}
	for _, a := range anomalies {
		fmt.Fprintln(stderr, "note:", a)
	}
	return writeJSON(stdout, child)
}

func cmdInspect(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("inspect", stderr)
	chainPath := fs.String("chain", "", "chain JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	chain, err := loadChain("chain", *chainPath)
	if err != nil {
		return err
	}
	printBody := func(prefix string, b core.SlipBody) {
		fmt.Fprintf(stdout, "%svendor=%s scopes=%s effects=%s budget=%.2f exp=%d depth=%d\n",
			prefix, b.Vendor, strings.Join(b.Scopes, ","), core.EffectNames(b.Effects), b.Budget, b.Exp, b.Depth)
		if len(b.Ceiling) > 0 {
			fmt.Fprintf(stdout, "%sceiling=%s\n", prefix, strings.Join(b.Ceiling, ","))
		}
		if b.Methods != 0 {
			fmt.Fprintf(stdout, "%smethods=%s\n", prefix, methodNames(b.Methods))
		}
		if len(b.Resources) > 0 {
			fmt.Fprintf(stdout, "%sresources=%s\n", prefix, strings.Join(b.Resources, ","))
		}
	}
	for i, s := range chain {
		fmt.Fprintf(stdout, "link %d: %s → %s… (nonce %s)\n", i, s.Body.Iss, short(s.Body.Aud), s.Body.Nonce)
		printBody("  ", s.Body)
	}
	var anomalies []string
	eff := core.Fold(chain, func(m string) { anomalies = append(anomalies, m) })
	fmt.Fprintln(stdout, "folded:")
	printBody("  ", eff)
	for _, a := range anomalies {
		fmt.Fprintln(stdout, "anomaly:", a)
	}
	return nil
}

// parseRoots parses repeated --root name=pubhex pairs into a RootStore.
func parseRoots(vals []string) (core.MapRootStore, error) {
	roots := core.MapRootStore{}
	for _, v := range vals {
		name, pub, ok := strings.Cut(v, "=")
		if !ok {
			return nil, fmt.Errorf("--root must be name=pubhex, got %q", v)
		}
		roots[name] = pub
	}
	return roots, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("verify", stderr)
	chainPath := fs.String("chain", "", "chain JSON file")
	priv := fs.String("priv", "", "HOLDER's private key (hex) — enables full proof-of-possession verify")
	now := fs.Int64("now", 0, "clock override, unix ms")
	var roots stringList
	fs.Var(&roots, "root", "trusted root, name=pubhex (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	chain, err := loadChain("chain", *chainPath)
	if err != nil {
		return err
	}
	rs, err := parseRoots(roots)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return fmt.Errorf("empty chain")
	}
	holder := chain[len(chain)-1].Body.Aud
	mode := "structural (no proof-of-possession — pass --priv to verify as the holder)"
	var res core.VerifyResult
	if *priv != "" {
		key, err := parsePriv(*priv)
		if err != nil {
			return err
		}
		probe := []byte("delegent-cli-verify-" + nonce())
		sig := hex.EncodeToString(ed25519.Sign(key, probe))
		pub := core.NewEd25519Signer(key).Public()
		res = core.VerifyChain(chain, pub, sig, probe, rs, nowMillis(*now))
		mode = "full (holder proof-of-possession)"
	} else {
		res = verifyStructural(chain, rs, nowMillis(*now))
	}
	out := map[string]any{"ok": res.OK, "mode": mode, "holder": holder}
	if res.OK {
		out["effective"] = res.Effective
		if len(res.Anomalies) > 0 {
			out["anomalies"] = res.Anomalies
		}
	} else {
		out["reason"] = res.Reason
	}
	if err := writeJSON(stdout, out); err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("chain verification failed: %s", res.Reason)
	}
	return nil
}

// verifyStructural checks everything VerifyChain does EXCEPT holder proof-of-possession
// (trusted root, link continuity, every signature, expiry, depth) — the auditor's view, since
// only the holder has the bound private key. It runs the real VerifyChain with the chain's own
// audience and a deliberately invalid possession signature: reaching the possession step means
// every earlier check passed, and exactly that failure (matched via the exported sentinel, not
// prose) is translated into structural success. The audience must still LOOK like a key — a
// chain bound to garbage can never be redeemed and must not verify.
func verifyStructural(chain core.Chain, roots core.RootStore, now int64) core.VerifyResult {
	holder := chain[len(chain)-1].Body.Aud
	if !hexPub.MatchString(holder) {
		return core.VerifyResult{OK: false, Reason: "audience is not a valid ed25519 public key"}
	}
	probe := []byte("delegent-cli-structural")
	res := core.VerifyChain(chain, holder, "00", probe, roots, now)
	if !res.OK && res.Reason == core.ReasonPossessionFailed {
		// every earlier check passed; recompute the fold for the effective view
		var anomalies []string
		eff := core.Fold(chain, func(m string) { anomalies = append(anomalies, m) })
		return core.VerifyResult{OK: true, Effective: eff, Anomalies: anomalies}
	}
	return res
}

func cmdHashReceipts(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("hash-receipts", stderr)
	path := fs.String("receipts", "", "receipts JSON array file")
	priv := fs.String("priv", "", "principal's root private key (hex) — also SIGN each receipt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rs, err := loadReceipts(*path)
	if err != nil {
		return err
	}
	var key ed25519.PrivateKey
	if *priv != "" {
		if key, err = parsePriv(*priv); err != nil {
			return err
		}
	}
	stripped := 0
	prev := ""
	for i := range rs {
		rs[i].PrevHash = prev
		rs[i].Hash = core.ReceiptHash(&rs[i], prev)
		switch {
		case key != nil:
			rs[i].Sig = hex.EncodeToString(ed25519.Sign(key, []byte(rs[i].Hash)))
		case rs[i].Sig != "":
			// a pre-existing signature covers the OLD hash — carrying it forward would produce
			// a chain that fails authenticity. Strip it and say so.
			rs[i].Sig = ""
			stripped++
		}
		prev = rs[i].Hash
	}
	if stripped > 0 {
		fmt.Fprintf(stderr, "note: stripped %d stale signature(s) — re-hashing invalidates them; pass --priv to re-sign\n", stripped)
	}
	return writeJSON(stdout, rs)
}

func cmdVerifyReceipts(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("verify-receipts", stderr)
	path := fs.String("receipts", "", "receipts JSON array file (chain order, one principal)")
	pub := fs.String("pub", "", "the principal's root public key (hex)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rs, err := loadReceipts(*path)
	if err != nil {
		return err
	}
	if *pub == "" {
		for _, r := range rs {
			if r.Sig != "" {
				return fmt.Errorf("this chain carries signatures — --pub is required to verify authenticity")
			}
		}
	}
	st := core.VerifyReceiptChain(rs, *pub)
	if err := writeJSON(stdout, st); err != nil {
		return err
	}
	if !st.Verified {
		return fmt.Errorf("receipt chain broken at %s: %s", st.BrokenAt, st.Reason)
	}
	return nil
}

func loadReceipts(path string) ([]core.Receipt, error) {
	if path == "" {
		return nil, fmt.Errorf("--receipts is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rs []core.Receipt
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("parse receipts %s: %w", path, err)
	}
	return rs, nil
}

func short(pub string) string {
	if len(pub) > 12 {
		return pub[:12]
	}
	return pub
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	return enc.Encode(v)
}
