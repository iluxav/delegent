package protocol

import "fmt"

// Fold collapses a chain into its effective slip. Widening is impossible BY
// CONSTRUCTION: a malicious child claiming every effect bit is simply ignored, because
// {read,write,destructive,…} & {read} = {read}. We do not validate-and-reject widening;
// the fold makes it a no-op. Attempts are reported via onAnomaly (may be nil), never
// hidden. Every field folds by the operation its TYPE demands: sets intersect, ordered
// scalars take the min. Identity fields (v/iss/aud/vendor/nonce) keep the root's.
func Fold(chain Chain, onAnomaly func(string)) SlipBody {
	acc := chain[0].Body
	for i := 1; i < len(chain); i++ {
		b := chain[i].Body
		if onAnomaly != nil {
			if b.Effects&acc.Effects != b.Effects {
				onAnomaly(fmt.Sprintf("widening attempt: child effects [%s] ⊄ parent [%s] (clamped)", EffectNames(b.Effects), EffectNames(acc.Effects)))
			}
			if b.Methods&acc.Methods != b.Methods {
				onAnomaly(fmt.Sprintf("widening attempt: child methods %d ⊄ parent %d (clamped)", b.Methods, acc.Methods))
			}
			if !everyIn(b.Scopes, acc.Scopes) {
				onAnomaly(fmt.Sprintf("widening attempt: child scopes [%s] ⊄ parent [%s] (clamped)", joinCsv(b.Scopes), joinCsv(acc.Scopes)))
			}
			if !everyIn(b.Ceiling, acc.Ceiling) {
				onAnomaly(fmt.Sprintf("widening attempt: child ceiling [%s] ⊄ parent [%s] (clamped)", joinCsv(b.Ceiling), joinCsv(acc.Ceiling)))
			}
			if b.Budget > acc.Budget {
				onAnomaly(fmt.Sprintf("widening attempt: child budget $%s > parent $%s (clamped)", jsNumber(b.Budget), jsNumber(acc.Budget)))
			}
		}
		acc = SlipBody{
			V: acc.V, Iss: acc.Iss, Aud: acc.Aud, Vendor: acc.Vendor, Nonce: acc.Nonce,
			Effects:   acc.Effects & b.Effects, // SET intersection, not min
			Methods:   acc.Methods & b.Methods,
			Scopes:    filterIn(acc.Scopes, b.Scopes),
			Ceiling:   filterIn(acc.Ceiling, b.Ceiling),
			Resources: foldResources(acc.Resources, b.Resources),
			Budget:    min(acc.Budget, b.Budget),
			Exp:       min(acc.Exp, b.Exp),
			Depth:     min(acc.Depth, b.Depth),
		}
	}
	return acc
}

// foldResources keeps only child prefixes that live under some parent prefix.
func foldResources(parent, child []string) []string {
	out := make([]string, 0)
	for _, c := range child {
		for _, p := range parent {
			if len(c) >= len(p) && c[:len(p)] == p {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// filterIn keeps items of a that are also in b (set intersection preserving a's order).
func filterIn(a, b []string) []string {
	out := make([]string, 0)
	for _, s := range a {
		if sliceContains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func everyIn(a, b []string) bool {
	for _, s := range a {
		if !sliceContains(b, s) {
			return false
		}
	}
	return true
}

func joinCsv(xs []string) string {
	out := ""
	for i, s := range xs {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
