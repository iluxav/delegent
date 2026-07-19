package protocol

import (
	"reflect"
	"strings"
)

// Path + body matching for real vendor APIs. Two things here are security-critical:
// normalization-before-matching (see NormalizeResource) and first-match-wins ordering
// (the caller iterates rules top to bottom).

// segs splits a path into non-empty segments.
func segs(p string) []string {
	out := make([]string, 0)
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// MatchPath matches a path against a pattern:
//
//	{name}  — exactly one segment (a path parameter)
//	*       — exactly one segment (wildcard)
//	**      — the remainder (zero or more segments); only meaningful at the end
func MatchPath(pattern, path string) bool {
	P := segs(pattern)
	S := segs(path)
	for i := 0; i < len(P); i++ {
		p := P[i]
		if p == "**" {
			return true // swallows the rest, including nothing
		}
		if i >= len(S) {
			return false // pattern still has segments, path ran out
		}
		if p == "*" || (strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}")) {
			continue // one segment, any value
		}
		if p != S[i] {
			return false
		}
	}
	return len(P) == len(S) // no '**' => lengths must agree exactly
}

// At reads a dotted path out of a body: "params.name" -> body.params.name. Missing or
// a non-object mid-path -> (nil, false).
func At(body any, path string) (any, bool) {
	cur := body
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, present := m[k]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// MatchBody checks a body predicate: every (possibly dotted) key must be present in
// the body with an equal value. This is what makes classification BODY-AWARE — it is
// the only reason a force-push can be distinguished from an ordinary ref update.
func MatchBody(pred map[string]any, body any) bool {
	if len(pred) == 0 {
		return true // no predicate => the rule does not care about the body
	}
	if body == nil {
		return false // predicate present but no body => cannot satisfy it
	}
	for k, v := range pred {
		got, present := At(body, k)
		if !present || !reflect.DeepEqual(got, v) {
			return false
		}
	}
	return true
}

// IsBatch reports whether a body is a JSON-RPC batch (an array).
func IsBatch(body any) bool {
	_, ok := body.([]any)
	return ok
}

func sliceContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
