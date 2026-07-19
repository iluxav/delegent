package protocol

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

// TestCanonicalVectors checks byte-exact parity with the TypeScript canonical() over
// vectors generated from the reference implementation (see scripts/gen-canonical.ts).
// If this fails, no signature will verify across the TS and Go implementations.
func TestCanonicalVectors(t *testing.T) {
	f, err := os.Open("testdata/canonical_vectors.jsonl")
	if err != nil {
		t.Fatalf("open vectors: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var vec struct {
			In  json.RawMessage `json:"in"`
			Out string          `json:"out"`
		}
		if err := json.Unmarshal(line, &vec); err != nil {
			t.Fatalf("vector %d parse: %v", n, err)
		}
		var in any
		if err := json.Unmarshal(vec.In, &in); err != nil {
			t.Fatalf("vector %d `in` parse: %v", n, err)
		}
		got := string(Canonical(in))
		if got != vec.Out {
			t.Errorf("vector %d mismatch\n in:   %s\n want: %s\n got:  %s", n, vec.In, vec.Out, got)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if n == 0 {
		t.Fatal("no vectors loaded")
	}
	t.Logf("checked %d canonical vectors", n)
}

// TestCanonicalSlipBodyTyped checks the SlipBody struct path (typed integers must
// render like JS numbers) against the exact bytes the TS reference produced.
func TestCanonicalSlipBodyTyped(t *testing.T) {
	sb := SlipBody{
		V: 1, Iss: "root:alice", Aud: "deadbeef", Vendor: "mcp-remote",
		Effects: 5, Methods: 2,
		Scopes: []string{"mcp:connect", "files:read"}, Ceiling: []string{"files:read"},
		Resources: []string{""}, Budget: 1, Exp: 1784067593323, Depth: 1, Nonce: "abc123",
	}
	want := `{"aud":"deadbeef","budget":1,"ceiling":["files:read"],"depth":1,"effects":5,"exp":1784067593323,"iss":"root:alice","methods":2,"nonce":"abc123","resources":[""],"scopes":["mcp:connect","files:read"],"v":1,"vendor":"mcp-remote"}`
	if got := string(Canonical(sb)); got != want {
		t.Errorf("SlipBody canonical mismatch\n want: %s\n got:  %s", want, got)
	}
}
