package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"delegent.dev/gateway"
	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
	"delegent.dev/gateway/telegram"
)

// cmdServe runs the HTTP gateway: the aggregate /mcp endpoint (plus /mcp/{target} for
// pinning), and the /admin surface the approvals/telegram CLI commands talk to.
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	home := homeFlag(fs)
	addr := fs.String("addr", "", "listen address (default: config listen_addr)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetOutput(os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}
	if *addr != "" {
		e.cfg.ListenAddr = *addr
	}

	registry := gateway.NewRegistry(e.st, e.sealer)

	// telegram approvals: configured through /admin (sealed token + settings row) and
	// hot-reloaded there; Reload here converges on whatever is stored.
	tgm := telegram.NewManager(telegram.ManagerOptions{
		Store: e.st, Secrets: secretstore.NewDB(e.st, e.sealer), Resolver: registry, ConsoleURL: e.cfg.ConsoleURL,
	})
	registry.SetNotifier(tgm)
	if err := tgm.Reload(ctx); err != nil {
		log.Printf("⚠️ telegram channel reload failed: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp/{target}", registry)
	mux.HandleFunc("/mcp", registry.ServeAggregate)
	mux.HandleFunc("/mcp/{$}", registry.ServeAggregate)
	mountAdmin(mux, e, registry, tgm)

	cleanup, err := writeRunfile(e.home, e.cfg.ListenAddr, "serve")
	if err != nil {
		return err
	}
	defer cleanup()

	srv := &http.Server{Addr: e.cfg.ListenAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		cleanup()
		_ = srv.Close()
	}()
	log.Printf("[delegent] build %s | operator %s | up — http://%s/mcp (agents) and /admin (CLI)",
		version, e.operator, e.cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// cmdStdio serves the identical aggregate surface over stdin/stdout — the transport MCP
// clients use to launch local servers. The agent key comes from --key or DELEGENT_AGENT_KEY;
// stdout belongs to the protocol, so all logging goes to stderr and pending consents are
// resolved out-of-band (telegram, or 'delegent approvals' against a running serve —
// elicitation-capable clients approve inline).
func cmdStdio(args []string) error {
	fs := flag.NewFlagSet("stdio", flag.ExitOnError)
	home := homeFlag(fs)
	key := fs.String("key", os.Getenv("DELEGENT_AGENT_KEY"), "agent key (or env DELEGENT_AGENT_KEY)")
	withTelegram := fs.Bool("telegram", false, "run the telegram approvals poller in this process (leave off when serve or another stdio instance already polls the bot)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetOutput(os.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}

	user := e.operator
	if gateway.AuthRequired(e.st) {
		if *key == "" {
			return errors.New("stdio needs an agent key: --key, or DELEGENT_AGENT_KEY (mint one with 'delegent key mint')")
		}
		k, err := e.st.GetAgentKeyByHash(ctx, agentkey.Hash(strings.TrimSpace(*key)))
		if err != nil {
			return errors.New("agent key not recognized")
		}
		if k.RevokedAt != 0 {
			return errors.New("agent key is revoked")
		}
		_ = e.st.TouchAgentKey(ctx, k.ID, nowMillis())
		user = k.UserID
	}

	registry := gateway.NewRegistry(e.st, e.sealer)
	tgm := telegram.NewManager(telegram.ManagerOptions{
		Store: e.st, Secrets: secretstore.NewDB(e.st, e.sealer), Resolver: registry, ConsoleURL: e.cfg.ConsoleURL,
	})
	registry.SetNotifier(tgm)
	// The poller runs only on request: another process (serve, or a second stdio instance)
	// may already be polling the bot token, and telegram allows one poller per token.
	if *withTelegram {
		if err := tgm.Reload(ctx); err != nil {
			log.Printf("⚠️ telegram channel reload failed: %v", err)
		}
	}

	// The admin surface rides a loopback listener on an EPHEMERAL port (no clashes when
	// several MCP clients each launch their own stdio gateway) and registers a runfile so
	// the dashboard can discover this instance. stdout belongs to MCP; admin is HTTP-only.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	adminMux := http.NewServeMux()
	mountAdmin(adminMux, e, registry, tgm)
	go func() { _ = http.Serve(ln, adminMux) }()
	cleanup, err := writeRunfile(e.home, ln.Addr().String(), "stdio")
	if err != nil {
		return err
	}
	defer cleanup()
	defer ln.Close()

	log.Printf("[delegent] stdio up — operator %s | admin http://%s", user, ln.Addr())
	return registry.ServeStdio(ctx, user)
}

// --- the /admin surface (bearer = config admin_token) ---

type adminEnv struct {
	e   *env
	reg *gateway.Registry
	tgm *telegram.Manager
}

func mountAdmin(mux *http.ServeMux, e *env, reg *gateway.Registry, tgm *telegram.Manager) {
	a := &adminEnv{e: e, reg: reg, tgm: tgm}
	guard := func(h http.HandlerFunc) http.Handler { return a.auth(h) }
	mux.Handle("GET /admin/consents", guard(a.listConsents))
	mux.Handle("POST /admin/consents/{id}", guard(a.resolveConsent))
	mux.Handle("GET /admin/consents/stream", guard(a.streamConsents))
	mux.Handle("POST /admin/telegram", guard(a.telegramSetup))
	mux.Handle("POST /admin/telegram/link", guard(a.telegramLink))
	// dashboard surface (admin.go)
	mux.Handle("GET /admin/targets", guard(a.listTargets))
	mux.Handle("GET /admin/targets/{id}", guard(a.getTargetDetail))
	mux.Handle("PUT /admin/targets/{id}/policy", guard(a.putTargetPolicy))
	mux.Handle("PUT /admin/targets/{id}/enabled", guard(a.setTargetEnabled))
	mux.Handle("POST /admin/targets/{id}/introspect", guard(a.introspectTarget))
	mux.Handle("PUT /admin/entitlements/{target}", guard(a.putEntitlement))
	mux.Handle("GET /admin/keys", guard(a.listKeys))
	mux.Handle("POST /admin/keys", guard(a.mintKey))
	mux.Handle("POST /admin/keys/{id}/revoke", guard(a.revokeKey))
	mux.Handle("PUT /admin/keys/{id}/channels", guard(a.setKeyChannels))
	mux.Handle("POST /admin/keys/{id}/roll", guard(a.rollKey))
	mux.Handle("GET /admin/events", guard(a.listEvents))
	mux.Handle("GET /admin/health", guard(a.health))
}

// health answers the dashboard's discovery ping with who/what this process is.
func (a *adminEnv) health(w http.ResponseWriter, r *http.Request) {
	adminJSON(w, http.StatusOK, map[string]any{"ok": true, "operator": a.e.operator, "version": version, "pid": os.Getpid()})
}

func (a *adminEnv) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.e.cfg.AdminToken == "" ||
			subtle.ConstantTimeCompare([]byte(tok), []byte(a.e.cfg.AdminToken)) != 1 {
			http.Error(w, `{"error":"admin token required"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	})
}

func adminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// listConsents returns both live parked asks (an agent is blocked on them right now) and
// durable pending rows (the ask outlived its call; approval lands on the agent's retry).
func (a *adminEnv) listConsents(w http.ResponseWriter, r *http.Request) {
	parked, err := a.reg.ListConsentRequests(a.e.operator, false)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	adminJSON(w, http.StatusOK, map[string]any{
		"live":   a.reg.PendingConsents(a.e.operator),
		"parked": parked,
	})
}

type resolveReq struct {
	Approve    bool     `json:"approve"`
	Scopes     []string `json:"scopes"` // approve-only; empty = every requested scope
	TTLMinutes int      `json:"ttl_minutes"`
	BudgetUSD  float64  `json:"budget_usd"`
}

func (a *adminEnv) resolveConsent(w http.ResponseWriter, r *http.Request) {
	var req resolveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	id := r.PathValue("id")

	granted := []string(nil) // deny
	if req.Approve {
		granted = req.Scopes
		if len(granted) == 0 { // approve-all: resolve the ask's own scope list
			for _, p := range a.reg.PendingConsents(a.e.operator) {
				if p.ID != id {
					continue
				}
				for _, sc := range p.Scopes {
					granted = append(granted, sc.Scope)
				}
			}
			if len(granted) == 0 {
				if row, err := a.e.st.GetConsentRequest(r.Context(), id); err == nil {
					granted = row.Scopes
				}
			}
		}
		if len(granted) == 0 {
			adminJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing to grant: unknown ask and no --scopes given"})
			return
		}
	}

	ok, err := a.reg.ResolveConsent(a.e.operator, id, granted, req.TTLMinutes, req.BudgetUSD)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	adminJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

type telegramSetupReq struct {
	Token       string `json:"token"`
	BotUsername string `json:"bot_username"`
}

// telegramSetup seals the bot token, stores the display-safe settings row, and hot-reloads
// the manager — the same flow the hosted console's settings page drives.
func (a *adminEnv) telegramSetup(w http.ResponseWriter, r *http.Request) {
	var req telegramSetupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" || req.BotUsername == "" {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "token and bot_username are required"})
		return
	}
	ctx := r.Context()
	secrets := secretstore.NewDB(a.e.st, a.e.sealer)
	if err := secrets.Put(ctx, telegram.TokenSecretRef, req.Token); err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cfg, _ := json.Marshal(telegram.Settings{BotUsername: strings.TrimPrefix(req.BotUsername, "@")})
	if err := a.e.st.PutChannelSetting(ctx, &store.ChannelSetting{Kind: telegram.SettingsKind, Settings: cfg, UpdatedAt: nowMillis()}); err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := a.tgm.Reload(ctx); err != nil {
		adminJSON(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("stored, but the bot failed to start: %v", err)})
		return
	}
	adminJSON(w, http.StatusOK, map[string]string{"status": "telegram channel up"})
}

// telegramLink mints the single-use /start token that binds the operator's chat to this
// instance. Minted here (not in the CLI process) so the running poller sees it.
func (a *adminEnv) telegramLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok := randomToken(16)
	err := a.e.st.PutChannelLinkToken(ctx, &store.ChannelLinkToken{
		Token: tok, UserID: a.e.operator, Kind: telegram.SettingsKind,
		CreatedAt: nowMillis(), ExpiresAt: nowMillis() + 10*60*1000,
	})
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	bot := ""
	if s, err := a.e.st.GetChannelSetting(ctx, telegram.SettingsKind); err == nil {
		var cfg telegram.Settings
		_ = json.Unmarshal(s.Settings, &cfg)
		bot = cfg.BotUsername
	}
	adminJSON(w, http.StatusOK, map[string]string{"token": tok, "bot_username": bot})
}
