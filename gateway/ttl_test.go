package gateway

import (
	"testing"
)

func TestTTLOptions_DefaultAndEnv(t *testing.T) {
	t.Setenv("DELEGENT_TTL_OPTIONS", "")
	if got := ttlLabels(); len(got) != 3 || got[0] != "15m" {
		t.Fatalf("default labels = %v, want [15m 1h 8h]", got)
	}
	if ttlDefault().Label != "1h" {
		t.Fatalf("default option = %q, want 1h", ttlDefault().Label)
	}

	// Custom short options for testing — labels preserved, minutes parsed, floor at 1m.
	t.Setenv("DELEGENT_TTL_OPTIONS", "30s, 1m , 5m,garbage,")
	opts := ttlOptions()
	if len(opts) != 3 {
		t.Fatalf("parsed %d options, want 3 (garbage/empty skipped): %+v", len(opts), opts)
	}
	if opts[0].Label != "30s" || opts[0].Minutes != 1 { // sub-minute floored to 1
		t.Fatalf("30s → %+v, want {30s 1}", opts[0])
	}
	if opts[2].Label != "5m" || opts[2].Minutes != 5 {
		t.Fatalf("5m → %+v, want {5m 5}", opts[2])
	}

	// Default falls back to the first option when the requested default isn't present or "1h" is absent.
	t.Setenv("DELEGENT_TTL_DEFAULT", "1m")
	if ttlDefault().Label != "1m" {
		t.Fatalf("explicit default = %q, want 1m", ttlDefault().Label)
	}
	t.Setenv("DELEGENT_TTL_DEFAULT", "nope")
	if ttlDefault().Label != "30s" {
		t.Fatalf("bad default should fall to first option, got %q", ttlDefault().Label)
	}
}

func TestTTLMinutesForLabelAndClamp(t *testing.T) {
	t.Setenv("DELEGENT_TTL_OPTIONS", "1m,5m,10m")
	t.Setenv("DELEGENT_TTL_DEFAULT", "5m")

	if m := ttlMinutesForLabel("10m"); m != 10 {
		t.Fatalf("label 10m → %d, want 10", m)
	}
	if m := ttlMinutesForLabel("bogus"); m != 5 { // unknown label → default
		t.Fatalf("unknown label → %d, want default 5", m)
	}
	// Clamp: a decision can't exceed the largest configured option, and 0 → default.
	if m := ttlClampMinutes(9999); m != 10 {
		t.Fatalf("clamp 9999 → %d, want 10 (max option)", m)
	}
	if m := ttlClampMinutes(0); m != 5 {
		t.Fatalf("clamp 0 → %d, want default 5", m)
	}
	if m := ttlClampMinutes(3); m != 3 {
		t.Fatalf("clamp 3 → %d, want 3 (within range)", m)
	}
}
