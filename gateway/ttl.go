package gateway

import (
	"os"
	"strings"
	"time"
)

// TTL options for the consent dialogs are configurable via env so a grant's lifetime can be
// tuned (short values are handy for testing that cross-chat reuse expires). This will move to
// per-target DB config later; the env is the interim knob.
//
//	DELEGENT_TTL_OPTIONS  comma-separated durations offered in the dialog (default "15m,1h,8h").
//	                      Each is parsed with time.ParseDuration; the label shown is the raw
//	                      string. Granularity is whole MINUTES (sessions expire in minutes), so
//	                      anything under 1m is floored to 1m.
//	DELEGENT_TTL_DEFAULT  which option is pre-selected (must be one of the options; falls back
//	                      to "1h" if present, else the first option).
type ttlOption struct {
	Label   string `json:"label"`
	Minutes int    `json:"minutes"`
}

var defaultTTLOptions = []ttlOption{{"15m", 15}, {"1h", 60}, {"8h", 480}}

// ttlOptions parses DELEGENT_TTL_OPTIONS (read each call — cheap, only on consent — so tests
// and a live env change take effect without a restart). Invalid entries are skipped; an empty
// or all-invalid list falls back to the built-in defaults.
func ttlOptions() []ttlOption {
	raw := os.Getenv("DELEGENT_TTL_OPTIONS")
	if strings.TrimSpace(raw) == "" {
		return defaultTTLOptions
	}
	var opts []ttlOption
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		d, err := time.ParseDuration(p)
		if err != nil || d <= 0 {
			continue
		}
		m := int(d.Minutes())
		if m < 1 {
			m = 1 // session expiry is minute-granular; never mint a zero-length grant
		}
		opts = append(opts, ttlOption{Label: p, Minutes: m})
	}
	if len(opts) == 0 {
		return defaultTTLOptions
	}
	return opts
}

func ttlLabels() []string {
	opts := ttlOptions()
	out := make([]string, len(opts))
	for i, o := range opts {
		out[i] = o.Label
	}
	return out
}

// ttlDefault returns the pre-selected option: DELEGENT_TTL_DEFAULT if it names one of the
// options, else "1h" if present, else the first option.
func ttlDefault() ttlOption {
	opts := ttlOptions()
	want := strings.TrimSpace(os.Getenv("DELEGENT_TTL_DEFAULT"))
	for _, o := range opts {
		if o.Label == want {
			return o
		}
	}
	for _, o := range opts {
		if o.Label == "1h" {
			return o
		}
	}
	return opts[0]
}

// ttlMinutesForLabel maps a dialog label back to minutes, falling back to the default option
// for an unknown label (a client sending a stale/garbage label can never widen past config).
func ttlMinutesForLabel(label string) int {
	for _, o := range ttlOptions() {
		if o.Label == label {
			return o.Minutes
		}
	}
	return ttlDefault().Minutes
}

// ttlClampMinutes bounds a caller-supplied minute count to the largest configured option, so
// a widget/console decision cannot exceed the operator's configured ceiling. Zero/negative
// means "use the default".
func ttlClampMinutes(m int) int {
	if m <= 0 {
		return ttlDefault().Minutes
	}
	max := 0
	for _, o := range ttlOptions() {
		if o.Minutes > max {
			max = o.Minutes
		}
	}
	if m > max {
		return max
	}
	return m
}
