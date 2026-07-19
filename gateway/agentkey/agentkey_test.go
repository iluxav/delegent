package agentkey

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestNew_ShapeAndHash(t *testing.T) {
	full, hash, prefix := New()
	if !strings.HasPrefix(full, "dgk_") {
		t.Fatalf("missing scheme prefix: %s", full)
	}
	if prefix != full[:12] {
		t.Fatalf("prefix mismatch: %s vs %s", prefix, full[:12])
	}
	want := sha256.Sum256([]byte(full))
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("hash is not sha256 of the full token")
	}
	if bytes.Contains(hash, []byte(full)) {
		t.Fatal("hash must not contain the plaintext")
	}
}

func TestNew_Unique(t *testing.T) {
	a, _, _ := New()
	b, _, _ := New()
	if a == b {
		t.Fatal("two keys collided")
	}
}

func TestHash_Deterministic(t *testing.T) {
	if !bytes.Equal(Hash("dgk_abc"), Hash("dgk_abc")) {
		t.Fatal("Hash not deterministic")
	}
	if bytes.Equal(Hash("dgk_abc"), Hash("dgk_abd")) {
		t.Fatal("different tokens hashed equal")
	}
}
