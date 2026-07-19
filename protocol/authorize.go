package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// Authorize is the whole enforcement decision: the classified request's effect/method/
// scopes/resource/cost must all fit inside the effective slip. It is SUBSET, not ≤ —
// an effect the grant does not contain is not "too high", it is simply absent, and no
// ordering can smuggle it in. The deny reasons ARE the audit trail, so they name the
// specific thing refused.
func Authorize(e SlipBody, c Classified) Decision {
	unknownNote := ""
	if c.Unknown {
		unknownNote = fmt.Sprintf("unknown action '%s' → effect 'unknown' (fail closed): ", c.Action)
	}
	if c.Effect&e.Effects != c.Effect {
		return deny(fmt.Sprintf("%seffect '%s' not in grant [%s]", unknownNote, EffectNames(c.Effect), EffectNames(e.Effects)))
	}
	if c.Method&e.Methods != c.Method {
		return deny(fmt.Sprintf("method %s not permitted", MethodName(c.Method)))
	}
	var missing []string
	for _, s := range c.Scopes {
		if !sliceContains(e.Scopes, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return deny("scope(s) not granted: " + strings.Join(missing, ", "))
	}
	inGrant := false
	for _, p := range e.Resources {
		if strings.HasPrefix(c.Resource, p) {
			inGrant = true
			break
		}
	}
	if !inGrant {
		return deny(fmt.Sprintf("resource '%s' outside grant", c.Resource))
	}
	if c.Cost > e.Budget {
		return deny(fmt.Sprintf("cost $%s > budget $%s", jsNumber(c.Cost), strconv.FormatFloat(e.Budget, 'f', 2, 64)))
	}
	return allow()
}
