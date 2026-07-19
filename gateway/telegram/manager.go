package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"delegent.dev/gateway/store"
)

const (
	// SettingsKind is the channel_settings row key for this channel.
	SettingsKind = "telegram"
	// TokenSecretRef is where the bot token lives, SEALED, in the secret store — never in
	// channel_settings and never in an API response.
	TokenSecretRef = "channel:telegram:token"
)

// Settings is the display-safe configuration stored in channel_settings.settings.
type Settings struct {
	BotUsername string `json:"bot_username"`
}

// Secrets is the sealed-secret port the manager needs (satisfied by secretstore.DB).
type Secrets interface {
	Get(ctx context.Context, ref string) (string, error)
	Put(ctx context.Context, ref, secret string) error
	Delete(ctx context.Context, ref string) error
}

// ManagerOptions wires the Manager. BaseURL/HTTPClient are test seams — empty means the real
// Bot API with the configured token.
type ManagerOptions struct {
	Store      store.Store
	Secrets    Secrets
	Resolver   ConsentResolver // nil disables the decision handler (link handshake still works)
	ConsoleURL string
	Now        func() int64
	BaseURL    string
	HTTPClient *http.Client
}

// Manager is the DB-configured runtime for the telegram channel. It is registered ONCE as the
// gateway registry's ConsentNotifier at boot; Reload() reads channel_settings + the sealed bot
// token and swaps the inner client/notifier and (re)starts the poller — configure, change, or
// remove the bot at runtime with no restart. Unconfigured, every surface is a silent no-op.
type Manager struct {
	opts ManagerOptions

	mu       sync.Mutex
	inner    *Notifier
	username string
	cancel   context.CancelFunc // stops the current poller; nil when none runs
}

func NewManager(o ManagerOptions) *Manager {
	if o.Now == nil {
		o.Now = func() int64 { return time.Now().UnixMilli() }
	}
	return &Manager{opts: o}
}

// ConsentParked implements gateway.ConsentNotifier by delegating to the current notifier.
func (m *Manager) ConsentParked(r *store.ConsentRequest) {
	m.mu.Lock()
	n := m.inner
	m.mu.Unlock()
	if n != nil {
		n.ConsentParked(r)
	}
}

// BotUsername reports the configured bot (for the console's connect deep link).
func (m *Manager) BotUsername() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.username, m.username != ""
}

// Stop halts the poller and clears state (shutdown/tests).
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.inner = nil
	m.username = ""
}

// Reload re-reads the channel configuration and converges the runtime on it: configured →
// fresh client + notifier + poller (replacing any previous); absent/unreadable → everything
// stops. Safe to call from any goroutine, any number of times.
func (m *Manager) Reload(ctx context.Context) error {
	row, err := m.opts.Store.GetChannelSetting(ctx, SettingsKind)
	if errors.Is(err, store.ErrNotFound) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.stopLocked()
		return nil
	}
	if err != nil {
		return err
	}
	var s Settings
	if err := json.Unmarshal(row.Settings, &s); err != nil {
		return err
	}
	token, err := m.opts.Secrets.Get(ctx, TokenSecretRef)
	if err != nil {
		// half-configured (settings row without a sealed token) reads as unconfigured — the
		// settings API writes both together, so this is a transient or a manual DB edit.
		log.Printf("[telegram] settings present but token unreadable (%v) — channel disabled", err)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.stopLocked()
		return nil
	}

	var client *Client
	if m.opts.BaseURL != "" {
		hc := m.opts.HTTPClient
		if hc == nil {
			hc = &http.Client{Timeout: 60 * time.Second}
		}
		client = NewWithBase(m.opts.BaseURL, hc)
	} else {
		client = New(token)
	}

	handlers := Handlers{OnLink: NewLinkHandler(m.opts.Store, m.opts.Now)}
	if m.opts.Resolver != nil {
		handlers.OnDecision = NewDecisionHandler(m.opts.Store, m.opts.Resolver)
	}
	pollCtx, cancel := context.WithCancel(context.Background())
	go client.Poll(pollCtx, handlers)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel() // retire the previous poller only once its replacement is ready
	}
	m.cancel = cancel
	m.inner = NewNotifier(client, m.opts.Store, m.opts.ConsoleURL)
	m.username = s.BotUsername
	log.Printf("[telegram] channel configured (bot @%s)", s.BotUsername)
	return nil
}
