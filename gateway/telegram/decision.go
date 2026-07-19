package telegram

import (
	"context"
	"log"
	"strings"

	"delegent.dev/gateway/store"
)

// ConsentResolver is the console's own decision path (satisfied by gateway.Registry): the
// telegram side adds no authority of its own — a tap runs through exactly the machinery a
// console GRANT/DENY does, including the owner scoping.
type ConsentResolver interface {
	ResolveConsent(owner, id string, granted []string, ttlMinutes int, budgetUSD float64) (ok bool, err error)
}

// NewDecisionHandler returns the poller's Approve/Deny dispatcher. Trust chain: the request
// row names its owner; the owner's linked telegram chat is the ONLY chat allowed to resolve
// it (a forwarded notice or a second group member can't). Approve grants exactly the scopes
// asked (zero ttl/budget = server defaults); fine-grained narrowing stays a console affair.
// The returned text replaces the notice message.
func NewDecisionHandler(st store.Store, resolver ConsentResolver) DecisionHandler {
	return func(ctx context.Context, requestID, decision, chatID, username string) string {
		r, err := st.GetConsentRequest(ctx, requestID)
		if err != nil {
			return "🤷 This request is unknown or has expired — check the console."
		}
		conn, err := st.GetChannelConnection(ctx, r.Principal, "telegram")
		if err != nil || conn.Address != chatID {
			log.Printf("[telegram] REFUSED decision on %s: chat %s is not the owner's linked chat", requestID, chatID)
			return "⛔ This chat is not authorized to resolve this request."
		}
		granted := r.Scopes
		if decision == "deny" {
			granted = nil
		}
		ok, err := resolver.ResolveConsent(r.Principal, requestID, granted, 0, 0)
		if err != nil {
			log.Printf("[telegram] resolve %s failed: %v", requestID, err)
			return "⚠️ Something went wrong applying the decision — use the console."
		}
		if !ok {
			return "🕐 This request is no longer active (expired or already handled) — the agent will ask again if it still needs access."
		}
		agent := r.AgentName
		if agent == "" {
			agent = "the agent"
		}
		if decision == "deny" {
			return "❌ Denied — " + agent + " gets no access on " + r.TargetID + "."
		}
		return "✅ Approved — " + agent + " granted " + strings.Join(r.Scopes, ", ") + " on " + r.TargetID + "."
	}
}
