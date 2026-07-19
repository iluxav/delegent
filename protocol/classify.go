package protocol

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Request is what gets classified: an action name (or HTTP method), a resource id (or
// URL path), an optional metered amount, and a body that is either an object
// (map[string]any) or a JSON-RPC batch ([]any).
type Request struct {
	Action   string
	Resource string
	Amount   float64
	Body     any
}

// Classified is the danger assessment of a Request against an adapter.
type Classified struct {
	Action   string
	Effect   Effect
	Method   Method
	Scopes   []string
	Resource string
	Cost     float64
	Unknown  bool // true => action not in the adapter, defaulted (fail closed)
}

var multiSlash = regexp.MustCompile(`/{2,}`)

// NormalizeResource decodes %xx (repeatedly), collapses '//', and resolves '.'/'..'
// BEFORE any prefix match happens. Path-matching bypasses are a classic auth hole:
// the string we match must be the string that will be requested.
func NormalizeResource(resource string) string {
	s := resource
	for i := 0; i < 5; i++ {
		decoded, err := url.PathUnescape(s) // decodes %xx, leaves '+' literal (like decodeURIComponent)
		if err != nil {
			break
		}
		if decoded == s {
			break
		}
		s = decoded
	}
	s = multiSlash.ReplaceAllString(s, "/")
	parts := make([]string, 0)
	for _, seg := range strings.Split(s, "/") {
		switch seg {
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		case ".":
			// skip
		default:
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, "/")
}

// Classify assigns an effect/method/scopes to a Request. A JSON-RPC batch is
// classified as the UNION of its elements — one unclassified element contributes the
// UNKNOWN bit and poisons the whole array, so a batch is allowed in full or not at all.
func Classify(a Adapter, r Request) Classified {
	if IsBatch(r.Body) {
		els := r.Body.([]any)
		out := Classified{
			Action:   fmt.Sprintf("batch[%d]", len(els)),
			Resource: NormalizeResource(r.Resource),
		}
		seen := map[string]bool{}
		for _, el := range els {
			p := Classify(a, Request{Action: r.Action, Resource: r.Resource, Amount: r.Amount, Body: el})
			out.Effect |= p.Effect
			out.Method |= p.Method
			out.Cost += p.Cost
			if p.Unknown {
				out.Unknown = true
			}
			for _, s := range p.Scopes { // union, preserving first-appearance order (JS Set semantics)
				if !seen[s] {
					seen[s] = true
					out.Scopes = append(out.Scopes, s)
				}
			}
		}
		if out.Scopes == nil {
			out.Scopes = []string{}
		}
		return out
	}

	action := r.Action
	body := r.Body
	resource := NormalizeResource(r.Resource)

	var rule *ClassifyRule
	for i := range a.Classify {
		k := &a.Classify[i]
		if k.Match == nil {
			continue // section-comment entry
		}
		m := k.Match
		if m.Action != nil {
			if *m.Action == action {
				rule = k
				break
			}
			continue // action rule that didn't match: never falls through to path checks
		}
		if m.Path != nil {
			if m.Method == nil || *m.Method != action {
				continue
			}
			if !MatchPath(*m.Path, resource) {
				continue
			}
			if !MatchBody(m.Body, body) {
				continue
			}
			rule = k
			break
		}
	}

	if rule == nil {
		// Unknown action FAILS CLOSED via the UNKNOWN bit. Name the thing refused: on MCP
		// every call is POST /mcp, so the tool (in the body) is the informative label.
		label := strings.TrimSpace(action + " " + resource)
		if tool, ok := At(body, "params.name"); ok {
			method, _ := At(body, "method")
			label = fmt.Sprintf("%v:%v", method, tool)
		}
		eff := EffectUnknown
		if e, ok := EffectByName(a.Default.Effect); ok {
			eff = e
		}
		return Classified{Action: label, Effect: eff, Method: 0, Scopes: []string{}, Resource: resource, Cost: 0, Unknown: true}
	}

	eff := EffectUnknown
	if e, ok := EffectByName(rule.Effect); ok { // unrecognised effect name => fail closed
		eff = e
	}
	var method Method
	name := rule.Method
	if name == nil && rule.Match != nil {
		name = rule.Match.Method
	}
	if name != nil {
		if bit, ok := MethodByName(*name); ok {
			method = bit
		}
	}
	cost := 0.0
	if sliceContains(rule.Meters, "amount") {
		cost = r.Amount
	}
	return Classified{Action: action, Effect: eff, Method: method, Scopes: rule.Scopes, Resource: resource, Cost: cost, Unknown: false}
}
