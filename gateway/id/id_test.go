package id

import (
	"strings"
	"testing"
)

func TestNew_PrefixAndShape(t *testing.T) {
	got := New("sess")
	if !strings.HasPrefix(got, "sess_") {
		t.Fatalf("missing prefix: %s", got)
	}
	if Prefix(got) != "sess" {
		t.Fatalf("Prefix = %q", Prefix(got))
	}
	if len(got) != len("sess_")+Size {
		t.Fatalf("unexpected length %d: %s", len(got), got)
	}
}

func TestNanoID_OnlyAlphabet(t *testing.T) {
	s := NanoID(1000)
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("char %q not in alphabet", c)
		}
	}
}

func TestNew_Unique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100_000; i++ {
		v := New("x")
		if seen[v] {
			t.Fatalf("collision at %d: %s", i, v)
		}
		seen[v] = true
	}
}

func TestAlphabetIs64(t *testing.T) {
	if len(alphabet) != 64 {
		t.Fatalf("alphabet must be 64 chars for unbiased mapping, got %d", len(alphabet))
	}
}
