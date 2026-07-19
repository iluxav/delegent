package protocol

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// loadMCPAdapter parses the REAL adapter both implementations share.
func loadMCPAdapter(t *testing.T) Adapter {
	t.Helper()
	data, err := os.ReadFile("testdata/adapters/mcp-remote/adapter.json")
	if err != nil {
		t.Fatalf("read adapter: %v", err)
	}
	var a Adapter
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatalf("parse adapter: %v", err)
	}
	return a
}

func eachVector(t *testing.T, path string, fn func(t *testing.T, n int, line []byte)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		line := append([]byte(nil), sc.Bytes()...)
		fn(t, n, line)
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if n == 0 {
		t.Fatalf("no vectors in %s", path)
	}
	t.Logf("checked %d vectors from %s", n, path)
}

type reqJSON struct {
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	Amount   float64         `json:"amount"`
	Body     json.RawMessage `json:"body"`
}

func (r reqJSON) toRequest(t *testing.T) Request {
	t.Helper()
	var body any
	if len(r.Body) > 0 {
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatalf("body parse: %v", err)
		}
	}
	return Request{Action: r.Action, Resource: r.Resource, Amount: r.Amount, Body: body}
}

// TestClassifyVectors: Go Classify must reproduce the TS classify() output exactly,
// against the same adapter.json.
func TestClassifyVectors(t *testing.T) {
	a := loadMCPAdapter(t)
	eachVector(t, "testdata/classify_vectors.jsonl", func(t *testing.T, n int, line []byte) {
		var vec struct {
			Request reqJSON `json:"request"`
			Want    struct {
				Action   string   `json:"action"`
				Effect   uint     `json:"effect"`
				Method   uint     `json:"method"`
				Scopes   []string `json:"scopes"`
				Resource string   `json:"resource"`
				Cost     float64  `json:"cost"`
				Unknown  bool     `json:"unknown"`
			} `json:"want"`
		}
		if err := json.Unmarshal(line, &vec); err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		got := Classify(a, vec.Request.toRequest(t))
		w := vec.Want
		if got.Action != w.Action || got.Effect != Effect(w.Effect) || got.Method != Method(w.Method) ||
			got.Resource != w.Resource || got.Cost != w.Cost || got.Unknown != w.Unknown ||
			!reflect.DeepEqual(got.Scopes, w.Scopes) {
			t.Errorf("classify vector %d mismatch\n req:  %s\n want: %+v\n got:  %+v", n, vec.Request.Body, w, got)
		}
	})
}

// TestAuthorizeVectors: Go Classify+Authorize must reproduce the TS decision AND the
// exact deny reason (the reasons are the audit trail).
func TestAuthorizeVectors(t *testing.T) {
	a := loadMCPAdapter(t)
	eachVector(t, "testdata/authorize_vectors.jsonl", func(t *testing.T, n int, line []byte) {
		var vec struct {
			Slip    SlipBody `json:"slip"`
			Request reqJSON  `json:"request"`
			Want    struct {
				Allow  bool   `json:"allow"`
				Reason string `json:"reason"`
			} `json:"want"`
		}
		if err := json.Unmarshal(line, &vec); err != nil {
			t.Fatalf("vector %d: %v", n, err)
		}
		d := Authorize(vec.Slip, Classify(a, vec.Request.toRequest(t)))
		if d.Allow != vec.Want.Allow || d.Reason != vec.Want.Reason {
			t.Errorf("authorize vector %d mismatch\n want: allow=%v reason=%q\n got:  allow=%v reason=%q",
				n, vec.Want.Allow, vec.Want.Reason, d.Allow, d.Reason)
		}
	})
}
