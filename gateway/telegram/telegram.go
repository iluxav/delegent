// Package telegram is the Bot API transport for out-of-band consent notifications (slice 1:
// outbound notices + the /start link handshake). It never sees vendor credentials or grants
// authority — it only formats parked-consent notices and binds chats to users. Decisions stay
// in the console until the poller/resolver slice adds approve/deny buttons.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one bot. The base URL already includes the bot token
// (https://api.telegram.org/bot<token>); tests inject an httptest server instead.
type Client struct {
	base string
	http *http.Client
}

// New builds a Client for the real Bot API from a BotFather token.
func New(token string) *Client {
	return NewWithBase("https://api.telegram.org/bot"+token, &http.Client{Timeout: 60 * time.Second})
}

// NewWithBase is the test seam: point the client at any Bot-API-shaped server.
func NewWithBase(base string, hc *http.Client) *Client {
	return &Client{base: base, http: hc}
}

// Notice is one parked-consent notification: the legible headline (same text the consent
// dialog shows — no credentials, no payloads) plus the console URL where it can be resolved.
// RequestID, when set, adds Approve/Deny callback buttons bound to that consent request.
type Notice struct {
	RequestID  string
	Headline   string
	ConsoleURL string
}

// SendConsentNotice posts the notice to a chat: Approve/Deny callback buttons (when the notice
// carries a request id) above an "Open console" URL button for fine-grained decisions.
//
// Telegram REJECTS the whole sendMessage when an inline URL button is not a public http(s)
// URL ("Wrong HTTP URL" — localhost dev consoles hit this). A non-button-safe console URL
// degrades to a plain text line so the notice still lands with its decision buttons.
func (c *Client) SendConsentNotice(ctx context.Context, chatID string, n Notice) error {
	var rows [][]map[string]any
	if n.RequestID != "" {
		rows = append(rows, []map[string]any{
			{"text": "✅ Approve", "callback_data": "d:grant:" + n.RequestID},
			{"text": "❌ Deny", "callback_data": "d:deny:" + n.RequestID},
		})
	}
	text := "🔐 Delegent approval needed\n\n" + n.Headline
	if buttonSafeURL(n.ConsoleURL) {
		rows = append(rows, []map[string]any{{"text": "🔍 Open console", "url": n.ConsoleURL}})
	} else if n.ConsoleURL != "" {
		text += "\n\nConsole: " + n.ConsoleURL
	}
	body := map[string]any{
		"chat_id":      chatID,
		"text":         text,
		"reply_markup": map[string]any{"inline_keyboard": rows},
	}
	return c.call(ctx, "sendMessage", body)
}

// buttonSafeURL reports whether Telegram will accept u as an inline keyboard URL button:
// public http(s) only — localhost/loopback hosts are rejected by the Bot API.
func buttonSafeURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") {
		return false
	}
	host := p.Hostname()
	switch host {
	case "", "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return false
	}
	return true
}

// sendText posts a plain message (the /start handshake reply).
func (c *Client) sendText(ctx context.Context, chatID, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{"chat_id": chatID, "text": text})
}

func (c *Client) call(ctx context.Context, method string, body map[string]any) error {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+method, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	if !out.OK {
		return fmt.Errorf("telegram %s: %s", method, out.Description)
	}
	return nil
}

// LinkHandler consumes a "/start <token>" handshake: it should redeem the token and bind
// chatID to the token's user, returning the reply to show in the chat ("" = no reply).
type LinkHandler func(ctx context.Context, token, chatID, username string) (reply string)

// DecisionHandler consumes an Approve/Deny button tap: decision is "grant" or "deny", chatID
// is the tapping chat (the handler must verify it belongs to the request's owner). The result
// string replaces the notice text — outcome shown, stale buttons gone.
type DecisionHandler func(ctx context.Context, requestID, decision, chatID, username string) (result string)

// Handlers bundles the poller's dispatch targets; either may be nil (those updates are skipped).
type Handlers struct {
	OnLink     LinkHandler
	OnDecision DecisionHandler
}

// update is the slice of the Bot API update shape this package needs.
type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		From struct {
			Username string `json:"username"`
		} `json:"from"`
		Text string `json:"text"`
	} `json:"message"`
	CallbackQuery *struct {
		ID   string `json:"id"`
		Data string `json:"data"`
		From struct {
			Username string `json:"username"`
		} `json:"from"`
		Message struct {
			MessageID int64 `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

// Poll long-polls getUpdates until ctx is done, dispatching "/start <token>" messages to
// h.OnLink and Approve/Deny callback taps to h.OnDecision; everything else is ignored.
// Errors are logged and retried after a short pause — the poller must outlive flaky networks.
func (c *Client) Poll(ctx context.Context, h Handlers) {
	var offset int64
	for ctx.Err() == nil {
		ups, err := c.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[telegram] getUpdates: %v — retrying", err)
			select {
			case <-time.After(3 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			switch {
			case u.CallbackQuery != nil && h.OnDecision != nil:
				c.dispatchCallback(ctx, u, h.OnDecision)
			case u.Message != nil && h.OnLink != nil:
				token, ok := strings.CutPrefix(strings.TrimSpace(u.Message.Text), "/start ")
				if !ok || token == "" {
					continue
				}
				chatID := strconv.FormatInt(u.Message.Chat.ID, 10)
				if reply := h.OnLink(ctx, strings.TrimSpace(token), chatID, u.Message.From.Username); reply != "" {
					// the confirmation must survive a shutdown that begins during the handshake —
					// detach it from the polling context (bounded so it can't hang teardown)
					rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
					err := c.sendText(rctx, chatID, reply)
					cancel()
					if err != nil {
						log.Printf("[telegram] link reply to %s failed: %v", chatID, err)
					}
				}
			}
		}
	}
}

// dispatchCallback handles one Approve/Deny tap: parse "d:<grant|deny>:<request-id>", hand it
// to the resolver, then answer the callback (stops the spinner) and edit the notice to the
// outcome. Answer/edit are detached from the polling context like the link reply — a decision
// that was applied must be reflected in the chat even if shutdown starts mid-tap.
func (c *Client) dispatchCallback(ctx context.Context, u update, onDecision DecisionHandler) {
	cb := u.CallbackQuery
	parts := strings.SplitN(cb.Data, ":", 3)
	if len(parts) != 3 || parts[0] != "d" || (parts[1] != "grant" && parts[1] != "deny") || parts[2] == "" {
		return // not ours (or malformed) — leave it unanswered
	}
	chatID := strconv.FormatInt(cb.Message.Chat.ID, 10)
	result := onDecision(ctx, parts[2], parts[1], chatID, cb.From.Username)

	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := c.call(rctx, "answerCallbackQuery", map[string]any{"callback_query_id": cb.ID}); err != nil {
		log.Printf("[telegram] answerCallbackQuery %s failed: %v", cb.ID, err)
	}
	if result == "" {
		return
	}
	if err := c.call(rctx, "editMessageText", map[string]any{
		"chat_id": chatID, "message_id": cb.Message.MessageID, "text": result,
	}); err != nil {
		log.Printf("[telegram] editMessageText for %s failed: %v", chatID, err)
	}
}

func (c *Client) getUpdates(ctx context.Context, offset int64) ([]update, error) {
	url := c.base + "/getUpdates?timeout=50"
	if offset > 0 {
		url += "&offset=" + strconv.FormatInt(offset, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("getUpdates not ok: %s", raw)
	}
	return out.Result, nil
}
