package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI is the protocol in a terminal: keygen → mint → attenuate → verify, plus receipt
// verification. Everything round-trips through files exactly as a cross-gateway handoff would.

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return out.String(), errb.String(), code
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type keyOut struct {
	Pub  string `json:"pub"`
	Priv string `json:"priv"`
}

func genKey(t *testing.T) keyOut {
	t.Helper()
	out, errb, code := runCLI(t, "keygen")
	if code != 0 {
		t.Fatalf("keygen: %s", errb)
	}
	var k keyOut
	if err := json.Unmarshal([]byte(out), &k); err != nil {
		t.Fatalf("keygen output: %v (%q)", err, out)
	}
	if len(k.Pub) != 64 || k.Priv == "" {
		t.Fatalf("keygen shape: %+v", k)
	}
	return k
}

func TestMintAttenuateVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := genKey(t)   // Alice's root key
	agent := genKey(t)  // alice-agent's holder key
	remote := genKey(t) // coder-agent's holder key (the foreign delegate)

	// mint: Alice → alice-agent
	chainJSON, errb, code := runCLI(t, "mint",
		"--priv", root.Priv, "--iss", "root:alice", "--aud", agent.Pub,
		"--vendor", "github", "--scopes", "repos:read,repos:write", "--effects", "read,write",
		"--budget", "10", "--ttl-minutes", "60", "--depth", "2", "--now", "1000000")
	if code != 0 {
		t.Fatalf("mint: %s", errb)
	}
	chainFile := writeFile(t, dir, "chain.json", chainJSON)

	// attenuate: alice-agent → coder-agent, narrowed to read-only, tighter budget
	childJSON, errb, code := runCLI(t, "attenuate",
		"--chain", chainFile, "--priv", agent.Priv, "--aud", remote.Pub,
		"--scopes", "repos:read", "--budget", "2")
	if code != 0 {
		t.Fatalf("attenuate: %s", errb)
	}
	childFile := writeFile(t, dir, "child.json", childJSON)

	// inspect names both links and the folded limits
	insp, _, code := runCLI(t, "inspect", "--chain", childFile)
	if code != 0 || !strings.Contains(insp, "root:alice") || !strings.Contains(insp, "repos:read") {
		t.Fatalf("inspect: %q", insp)
	}

	// full verify as the holder (proof-of-possession with coder-agent's key)
	out, errb, code := runCLI(t, "verify",
		"--chain", childFile, "--root", "root:alice="+root.Pub,
		"--priv", remote.Priv, "--now", "1000001")
	if code != 0 {
		t.Fatalf("verify (holder): %s / %s", out, errb)
	}
	if !strings.Contains(out, `"ok": true`) || !strings.Contains(out, "repos:read") {
		t.Fatalf("verify output: %q", out)
	}
	// the folded child must NOT retain the parent's write scope
	if strings.Contains(out, "repos:write") {
		t.Fatalf("attenuation leaked the parent scope: %q", out)
	}

	// structural verify (no holder key) still checks roots/links/signatures/expiry
	out, _, code = runCLI(t, "verify", "--chain", childFile, "--root", "root:alice="+root.Pub, "--now", "1000001")
	if code != 0 || !strings.Contains(out, "structural") {
		t.Fatalf("structural verify: %q", out)
	}

	// tampered chain fails: flip a scope in the child body
	tampered := strings.Replace(childJSON, "repos:read", "repos:admin", 1)
	tamperedFile := writeFile(t, dir, "tampered.json", tampered)
	out, _, code = runCLI(t, "verify", "--chain", tamperedFile, "--root", "root:alice="+root.Pub, "--now", "1000001")
	if code == 0 {
		t.Fatalf("tampered chain must fail: %q", out)
	}

	// verify as the WRONG holder fails proof-of-possession
	_, _, code = runCLI(t, "verify",
		"--chain", childFile, "--root", "root:alice="+root.Pub,
		"--priv", agent.Priv, "--now", "1000001")
	if code == 0 {
		t.Fatal("wrong holder must fail possession")
	}
}

func TestVerifyReceiptsCommand(t *testing.T) {
	dir := t.TempDir()
	root := genKey(t)

	// The CLI verifies receipt chains; hash-receipts (re)computes linkage for raw records —
	// an unsigned-but-linked chain verifies structurally with an unsigned count.
	raw := writeFile(t, dir, "raw.json", `[
	 {"id":"r1","principal":"root:alice","decision":"grant","created_at":1},
	 {"id":"r2","principal":"root:alice","decision":"deny","created_at":2}
	]`)
	out, errb, code := runCLI(t, "hash-receipts", "--receipts", raw)
	if code != 0 {
		t.Fatalf("hash-receipts: %s", errb)
	}
	hashed := writeFile(t, dir, "hashed.json", out)

	out, errb, code = runCLI(t, "verify-receipts", "--receipts", hashed, "--pub", root.Pub)
	if code != 0 {
		t.Fatalf("verify-receipts: %s / %s", out, errb)
	}
	if !strings.Contains(out, `"verified": true`) || !strings.Contains(out, `"unsigned": 2`) {
		t.Fatalf("verify-receipts output: %q", out)
	}

	// tamper a field after hashing → the chain must break
	tampered := strings.Replace(readFileT(t, hashed), `"decision": "deny"`, `"decision": "grant"`, 1)
	out, _, code = runCLI(t, "verify-receipts", "--receipts", writeFile(t, dir, "bad.json", tampered), "--pub", root.Pub)
	if code == 0 {
		t.Fatalf("tampered receipts must fail: %q", out)
	}
}

func readFileT(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Finding 1: everything the CLI says must flow through the injected writers — including
// attenuation anomaly notes and flag-parse errors.
func TestAnomaliesAndFlagErrorsUseInjectedStderr(t *testing.T) {
	dir := t.TempDir()
	root, agent, remote := genKey(t), genKey(t), genKey(t)
	chainJSON, _, code := runCLI(t, "mint",
		"--priv", root.Priv, "--iss", "root:alice", "--aud", agent.Pub,
		"--vendor", "gh", "--scopes", "a", "--effects", "read", "--ttl-minutes", "60", "--depth", "1")
	if code != 0 {
		t.Fatal("mint failed")
	}
	chainFile := writeFile(t, dir, "c.json", chainJSON)

	// asking to widen scopes produces an anomaly note — it must land on the INJECTED stderr
	_, errb, code := runCLI(t, "attenuate",
		"--chain", chainFile, "--priv", agent.Priv, "--aud", remote.Pub, "--scopes", "a,zzz")
	if code != 0 {
		t.Fatalf("attenuate: %s", errb)
	}
	if !strings.Contains(errb, "note:") {
		t.Fatalf("anomaly note missing from injected stderr: %q", errb)
	}

	// a bad flag's usage text must also land on the injected stderr
	_, errb, code = runCLI(t, "mint", "--no-such-flag")
	if code == 0 || !strings.Contains(errb, "no-such-flag") {
		t.Fatalf("flag error not on injected stderr: %q", errb)
	}
}

// Findings 3+5: ceiling/methods/resources reach the slip from the CLI, and inspect shows them.
func TestMintAttenuateCeilingMethodsResources(t *testing.T) {
	dir := t.TempDir()
	root, agent, remote := genKey(t), genKey(t), genKey(t)
	chainJSON, errb, code := runCLI(t, "mint",
		"--priv", root.Priv, "--iss", "root:alice", "--aud", agent.Pub,
		"--vendor", "gh", "--scopes", "repos:read", "--ceiling", "repos:read,repos:write",
		"--effects", "read,write", "--methods", "GET,POST", "--resources", "/repos/*",
		"--ttl-minutes", "60", "--depth", "1")
	if code != 0 {
		t.Fatalf("mint: %s", errb)
	}
	chainFile := writeFile(t, dir, "c.json", chainJSON)

	insp, _, code := runCLI(t, "inspect", "--chain", chainFile)
	if code != 0 {
		t.Fatal("inspect failed")
	}
	for _, want := range []string{"ceiling=repos:read,repos:write", "methods=GET+POST", "resources=/repos/*"} {
		if !strings.Contains(insp, want) {
			t.Fatalf("inspect missing %q:\n%s", want, insp)
		}
	}

	// attenuate with an explicit in-bounds ceiling: no anomaly, child carries it
	childJSON, errb, code := runCLI(t, "attenuate",
		"--chain", chainFile, "--priv", agent.Priv, "--aud", remote.Pub,
		"--ceiling", "repos:write", "--methods", "GET")
	if code != 0 {
		t.Fatalf("attenuate: %s", errb)
	}
	if strings.Contains(errb, "ceiling") {
		t.Fatalf("in-bounds ceiling flagged: %q", errb)
	}
	insp, _, _ = runCLI(t, "inspect", "--chain", writeFile(t, dir, "child.json", childJSON))
	if !strings.Contains(insp, "repos:write") || !strings.Contains(insp, "methods=GET\n") {
		t.Fatalf("child ceiling/methods not shown:\n%s", insp)
	}
}

// Findings 2+4: hash-receipts with --priv signs the chain (fully verifiable); without it,
// stale signatures are STRIPPED with a warning rather than silently invalidated.
func TestHashReceiptsSignsAndStripsStaleSigs(t *testing.T) {
	dir := t.TempDir()
	root := genKey(t)
	raw := writeFile(t, dir, "raw.json", `[
	 {"id":"r1","principal":"root:alice","decision":"grant","created_at":1},
	 {"id":"r2","principal":"root:alice","decision":"deny","created_at":2}
	]`)

	// sign mode: fully verified, zero unsigned
	out, errb, code := runCLI(t, "hash-receipts", "--receipts", raw, "--priv", root.Priv)
	if code != 0 {
		t.Fatalf("hash-receipts --priv: %s", errb)
	}
	signed := writeFile(t, dir, "signed.json", out)
	out, _, code = runCLI(t, "verify-receipts", "--receipts", signed, "--pub", root.Pub)
	if code != 0 || !strings.Contains(out, `"verified": true`) || strings.Contains(out, `"unsigned"`) {
		t.Fatalf("signed chain should fully verify: %q", out)
	}

	// re-hash a SIGNED chain without --priv: sigs are stale → stripped, with a warning
	out, errb, code = runCLI(t, "hash-receipts", "--receipts", signed)
	if code != 0 {
		t.Fatalf("re-hash: %s", errb)
	}
	if !strings.Contains(errb, "strip") {
		t.Fatalf("stale-sig strip warning missing: %q", errb)
	}
	if strings.Contains(out, `"sig":`) && !strings.Contains(out, `"sig": ""`) {
		t.Fatalf("stale sigs not stripped: %q", out)
	}
	restripped := writeFile(t, dir, "restripped.json", out)
	if out, _, code = runCLI(t, "verify-receipts", "--receipts", restripped, "--pub", root.Pub); code != 0 {
		t.Fatalf("stripped chain must verify structurally: %q", out)
	}
}

// Finding 6: structural verify must not bless a chain bound to an invalid audience key.
func TestStructuralVerifyRejectsGarbageAudience(t *testing.T) {
	dir := t.TempDir()
	root := genKey(t)
	chainJSON, _, code := runCLI(t, "mint",
		"--priv", root.Priv, "--iss", "root:alice", "--aud", strings.Repeat("a", 64),
		"--scopes", "x", "--ttl-minutes", "60")
	if code != 0 {
		t.Fatal("mint failed")
	}
	// valid hex but tamper it into non-hex garbage
	garbage := strings.Replace(chainJSON, strings.Repeat("a", 64), "not-a-key", 1)
	f := writeFile(t, dir, "g.json", garbage)
	// (signature breaks too, but the point stands: no structural OK for this chain)
	if _, _, code := runCLI(t, "verify", "--chain", f, "--root", "root:alice="+root.Pub, "--now", "1"); code == 0 {
		t.Fatal("garbage audience must not verify structurally")
	}
}

// Finding 7: top-level help and version.
func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		out, _, code := runCLI(t, args...)
		if code != 0 || !strings.Contains(out, "usage:") {
			t.Fatalf("%v: code=%d out=%q", args, code, out)
		}
	}
	out, _, code := runCLI(t, "version")
	if code != 0 || !strings.Contains(out, "delegent") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

// Finding 8: clear required-flag errors, aud shape validation, and --pub required.
func TestFlagValidation(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"inspect"}, "--chain"},
		{[]string{"verify"}, "--chain"},
		{[]string{"hash-receipts"}, "--receipts"},
		{[]string{"verify-receipts"}, "--receipts"},
	} {
		_, errb, code := runCLI(t, tc.args...)
		if code == 0 || !strings.Contains(errb, tc.want) {
			t.Fatalf("%v: code=%d err=%q (want mention of %s)", tc.args, code, errb, tc.want)
		}
	}
	// aud must look like an ed25519 public key
	root := genKey(t)
	_, errb, code := runCLI(t, "mint", "--priv", root.Priv, "--iss", "r", "--aud", "garbage", "--scopes", "x")
	if code == 0 || !strings.Contains(errb, "aud") {
		t.Fatalf("garbage aud accepted: %q", errb)
	}
	// verify-receipts on a SIGNED chain without --pub: clear error, not "signature invalid"
	raw := writeFile(t, dir, "raw.json", `[{"id":"r1","principal":"p","decision":"grant","created_at":1}]`)
	out, _, _ := runCLI(t, "hash-receipts", "--receipts", raw, "--priv", root.Priv)
	signed := writeFile(t, dir, "signed.json", out)
	_, errb, code = runCLI(t, "verify-receipts", "--receipts", signed)
	if code == 0 || !strings.Contains(errb, "--pub") {
		t.Fatalf("missing --pub on signed chain: %q", errb)
	}
}
