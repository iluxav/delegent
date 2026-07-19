package telegram

import (
	"context"
	"log"
	"strings"
	"time"

	"delegent.dev/gateway/store"
)

// Notifier satisfies the gateway's ConsentNotifier: when a console consent request parks, it
// pushes the legible headline to the owner's linked Telegram chat with an Open-console button.
// Advisory only — resolution still happens in the console (slice 2 adds in-chat buttons). An
// owner without a telegram connection is silently skipped.
type Notifier struct {
	c          *Client
	st         store.Store
	consoleURL string // console base, e.g. https://console.example (no trailing slash)
}

func NewNotifier(c *Client, st store.Store, consoleURL string) *Notifier {
	return &Notifier{c: c, st: st, consoleURL: strings.TrimRight(consoleURL, "/")}
}

// NewLinkHandler returns the /start-token redeemer the poller dispatches to: it consumes the
// single-use link token and binds the chat to the token's user (upsert — reconnecting moves
// the binding). The reply string is shown in the chat.
func NewLinkHandler(st store.Store, now func() int64) LinkHandler {
	return func(ctx context.Context, token, chatID, username string) string {
		lt, err := st.TakeChannelLinkToken(ctx, token, now())
		if err != nil {
			return "This link is invalid or expired. Generate a fresh one from the Delegent console."
		}
		label := ""
		if username != "" {
			label = "@" + username
		}
		if err := st.PutChannelConnection(ctx, &store.ChannelConnection{
			UserID: lt.UserID, Kind: lt.Kind, Address: chatID, Label: label, CreatedAt: now(),
		}); err != nil {
			log.Printf("[telegram] could not store connection for %s: %v", lt.UserID, err)
			return "Something went wrong on our side — try the link again from the console."
		}
		return "Connected ✅ — you'll get an approval notice here whenever an agent needs your consent."
	}
}

func (n *Notifier) ConsentParked(r *store.ConsentRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := n.st.GetChannelConnection(ctx, r.Principal, "telegram")
	if err != nil {
		return // not linked (or store hiccup) — the console remains the surface
	}
	// Parity: the persisted headline IS the dialogs' legible display (action, risk markers,
	// Why line) — use it verbatim, adding only the scope list the approve button will grant.
	// The assembled fallback covers rows that predate the headline field.
	var lines []string
	if r.Headline != "" {
		lines = []string{r.Headline}
	} else {
		agent := r.AgentName
		if agent == "" {
			agent = "An agent"
		}
		lines = []string{agent + " wants access on " + r.TargetID}
		if r.Reason != "" {
			lines = append(lines, "Why: "+r.Reason)
		}
	}
	lines = append(lines, "Scopes: "+strings.Join(r.Scopes, ", "))
	if err := n.c.SendConsentNotice(ctx, conn.Address, Notice{
		RequestID:  r.ID,
		Headline:   strings.Join(lines, "\n"),
		ConsoleURL: n.consoleURL + "/approvals",
	}); err != nil {
		log.Printf("[telegram] consent notice for %s to user %s failed: %v", r.ID, r.Principal, err)
	}
}
