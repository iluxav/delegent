package protocol

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Canonical produces the byte-exact serialization that signatures are computed over:
// sorted object keys, no whitespace, JS-JSON.stringify number/string formatting. It
// MUST match the TypeScript canonical() byte-for-byte or no signature ever verifies
// across the two implementations. Its parity is pinned by core/testdata vectors
// generated from the TS reference.
//
// Accepts the JSON value tree (nil, bool, string, numbers, []any/[]string,
// map[string]any) plus SlipBody directly. Callers building ad-hoc objects (e.g. the
// proxy's proof-of-possession bytes) pass a map[string]any.
func Canonical(v any) []byte {
	var b strings.Builder
	writeCanonical(&b, v)
	return []byte(b.String())
}

func writeCanonical(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		b.Write(jsonString(t))
	case int:
		b.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(t), 10))
	case Effect:
		b.WriteString(strconv.FormatUint(uint64(t), 10))
	case Method:
		b.WriteString(strconv.FormatUint(uint64(t), 10))
	case float64:
		b.WriteString(jsNumber(t))
	case json.Number:
		b.WriteString(string(t))
	case []any:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, el)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(jsonString(el))
		}
		b.WriteByte(']')
	case map[string]any:
		writeObject(b, t)
	case SlipBody:
		writeObject(b, slipToMap(t))
	default:
		// Fail loud in tests rather than sign over an ambiguous encoding.
		panic("canonical: unsupported type")
	}
}

func writeObject(b *strings.Builder, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonString(k))
		b.WriteByte(':')
		writeCanonical(b, m[k])
	}
	b.WriteByte('}')
}

// slipToMap converts a SlipBody to the generic tree with typed values, so integer
// fields render without a decimal point (matching JS) and keys are the json tags.
func slipToMap(s SlipBody) map[string]any {
	return map[string]any{
		"v": s.V, "iss": s.Iss, "aud": s.Aud, "vendor": s.Vendor,
		"effects": s.Effects, "methods": s.Methods,
		"scopes": s.Scopes, "ceiling": s.Ceiling, "resources": s.Resources,
		"budget": s.Budget, "exp": s.Exp, "depth": s.Depth, "nonce": s.Nonce,
	}
}

// jsonString encodes a string exactly like JS JSON.stringify: proper \u escaping of
// control characters, but NO HTML escaping of < > & (which encoding/json does by
// default and JS does not).
func jsonString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // appends a trailing '\n'
	out := buf.Bytes()
	return out[:len(out)-1]
}

// jsNumber renders a float like JS JSON.stringify: integer-valued floats print with
// no decimal ("1", "1000000000"), decimals use the shortest round-trip. The domain
// (budgets, ms timestamps) never reaches the magnitudes where JS switches to
// exponent notation, so 'f' with -1 precision is exact here.
func jsNumber(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "null" // JS JSON.stringify renders these as null
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}
