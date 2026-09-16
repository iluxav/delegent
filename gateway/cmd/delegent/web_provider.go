package main

// Delegent as an OAuth authorization server for its OWN /mcp endpoint.
//
// An agent that speaks OAuth (Claude, ChatGPT, …) needs no minted key: point it at the /mcp
// URL, it gets a 401 naming this server's metadata, registers itself, and sends the operator
// here to approve. The operator signs in with the SAME dashboard credentials and clicks Allow.
//
// The issued access token IS an agent key. That is the whole trick: every downstream check —
// entitlements, consent-channel policy, revocation, the activity log's key_name — already
// works on agent keys, so an OAuth connection is a first-class key that happens to have been
// minted by a browser instead of by hand. It shows up in the dashboard's key list and is
// revoked the same way.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/store"
)

const (
	// NOT "oauth_clients.json" — the store already owns that name for the per-target
	// registrations delegent holds as a CLIENT of other servers. These are the opposite:
	// agents that registered themselves with us.
	clientsFile = "oauth_inbound_clients.json"
	codeTTL     = 3 * time.Minute
)

// inboundClient is an agent that registered itself here (RFC 7591). Public clients only:
// PKCE is the proof, so there is no client secret to keep.
type inboundClient struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    int64    `json:"created_at"`
}

func (c *inboundClient) allows(redirect string) bool {
	for _, u := range c.RedirectURIs {
		if u == redirect {
			return true
		}
	}
	return false
}

// authCode is a single-use authorization code, bound to the client, the redirect it will be
// returned to, and the PKCE challenge. Kept in memory: it lives for seconds.
type authCode struct {
	ClientID, RedirectURI, Challenge, Scope, UserID string
	At                                              time.Time
}

// provider holds the authorization server's own state.
type provider struct {
	path string

	mu      sync.Mutex
	clients map[string]*inboundClient
	codes   map[string]*authCode
}

func newProvider(home string) (*provider, error) {
	p := &provider{path: filepath.Join(home, clientsFile), clients: map[string]*inboundClient{}, codes: map[string]*authCode{}}
	raw, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	// Unreadable registrations must never stop the gateway from serving agents: the worst case
	// is that a client re-registers, which every OAuth client already handles.
	if err := json.Unmarshal(raw, &p.clients); err != nil {
		log.Printf("⚠️ [delegent] ignoring %s: %v — agents will register again", clientsFile, err)
		p.clients = map[string]*inboundClient{}
	}
	return p, nil
}

// saveLocked persists registrations so an agent's client_id survives a restart. Callers hold mu.
func (p *provider) saveLocked() error {
	data, err := json.MarshalIndent(p.clients, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, append(data, '\n'), 0o600)
}

func (p *provider) client(id string) (*inboundClient, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.clients[id]
	return c, ok
}

func (p *provider) register(c *inboundClient) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[c.ID] = c
	return p.saveLocked()
}

func (p *provider) mintCode(code string, c *authCode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.codes { // sweep abandoned flows
		if time.Since(v.At) > codeTTL {
			delete(p.codes, k)
		}
	}
	p.codes[code] = c
}

// takeCode reads-and-deletes: an authorization code is good exactly once.
func (p *provider) takeCode(code string) (*authCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.codes[code]
	delete(p.codes, code)
	return c, ok && time.Since(c.At) <= codeTTL
}

// --- metadata ---

// baseURL is this server as the caller reached it, so metadata stays right behind a tunnel.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

func providerJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // metadata is public by design
	_ = json.NewEncoder(w).Encode(v)
}

// protectedResource answers RFC 9728 discovery. The path after the well-known prefix is the
// resource being asked about (/mcp, or /mcp/<target>), and it must echo back exactly what the
// client requested or the client rejects it.
func (w *webApp) protectedResource(rw http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	resource := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource")
	if resource == "" || resource == "/" {
		resource = "/mcp"
	}
	providerJSON(rw, map[string]any{
		"resource":                 base + resource,
		"authorization_servers":    []string{base},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
	})
}

// authServerMeta answers RFC 8414 discovery for this gateway acting as its own issuer.
func (w *webApp) authServerMeta(rw http.ResponseWriter, r *http.Request) {
	base := baseURL(r)
	providerJSON(rw, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"registration_endpoint":                 base + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"mcp"},
	})
}

// --- dynamic client registration ---

func (w *webApp) registerClient(rw http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
		oauthError(rw, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
		return
	}
	for _, u := range req.RedirectURIs {
		if _, err := url.Parse(u); err != nil {
			oauthError(rw, http.StatusBadRequest, "invalid_redirect_uri", "unparsable redirect_uri")
			return
		}
	}
	c := &inboundClient{ID: "dcl_" + randomToken(12), Name: req.ClientName, RedirectURIs: req.RedirectURIs, CreatedAt: nowMillis()}
	if err := w.prov.register(c); err != nil {
		oauthError(rw, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	log.Printf("[delegent] oauth: registered client %q (%s) → %s", c.Name, c.ID, strings.Join(c.RedirectURIs, " "))
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"client_id": c.ID, "client_name": c.Name, "redirect_uris": c.RedirectURIs,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code"},
		"response_types": []string{"code"}, "client_id_issued_at": c.CreatedAt / 1000,
	})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

// --- authorize ---

type consentView struct {
	Client, Redirect, State, Challenge, Scope, ClientID string
	User                                                string
}

// authorizePage is where the agent sends the operator. It requires a dashboard session — the
// same username and password that protects everything else here — and then asks, plainly,
// whether this agent may connect.
func (w *webApp) authorizePage(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, params, err := w.checkAuthorize(q)
	if err != nil {
		// Nothing is redirected anywhere until the client and redirect_uri check out.
		http.Error(rw, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !w.auth.configured() {
		http.Redirect(rw, r, "/setup", http.StatusSeeOther)
		return
	}
	if !w.auth.validSession(r) {
		http.Redirect(rw, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	params.Client = c.Name
	if params.Client == "" {
		params.Client = "An agent"
	}
	params.User = w.auth.username()
	w.render(rw, "oauthConsent", params)
}

// checkAuthorize validates everything that must hold before a human is asked anything.
func (w *webApp) checkAuthorize(q url.Values) (*inboundClient, consentView, error) {
	v := consentView{
		ClientID: q.Get("client_id"), Redirect: q.Get("redirect_uri"), State: q.Get("state"),
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope"),
	}
	c, ok := w.prov.client(v.ClientID)
	if !ok {
		return nil, v, errors.New("unknown client_id — register first")
	}
	if !c.allows(v.Redirect) {
		return nil, v, errors.New("redirect_uri does not match this client's registration")
	}
	if q.Get("response_type") != "code" {
		return nil, v, errors.New("only response_type=code is supported")
	}
	if v.Challenge == "" || q.Get("code_challenge_method") != "S256" {
		return nil, v, errors.New("PKCE with S256 is required")
	}
	return c, v, nil
}

// authorizeDecide records the operator's answer and hands control back to the agent.
func (w *webApp) authorizeDecide(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad form", http.StatusBadRequest)
		return
	}
	c, params, err := w.checkAuthorize(r.Form)
	if err != nil {
		http.Error(rw, "invalid authorization request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !w.auth.validSession(r) {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	redirect, err := url.Parse(params.Redirect)
	if err != nil {
		http.Error(rw, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	q := redirect.Query()
	if params.State != "" {
		q.Set("state", params.State)
	}
	if r.FormValue("action") != "allow" {
		q.Set("error", "access_denied")
		q.Set("error_description", "the operator declined")
		redirect.RawQuery = q.Encode()
		http.Redirect(rw, r, redirect.String(), http.StatusSeeOther)
		return
	}
	code := randomToken(24)
	w.prov.mintCode(code, &authCode{
		ClientID: c.ID, RedirectURI: params.Redirect, Challenge: params.Challenge,
		Scope: params.Scope, UserID: w.e.operator, At: time.Now(),
	})
	q.Set("code", code)
	redirect.RawQuery = q.Encode()
	log.Printf("[delegent] oauth: %s approved %q — code issued", w.auth.username(), c.Name)
	http.Redirect(rw, r, redirect.String(), http.StatusSeeOther)
}

// --- token ---

// token exchanges a code for an access token. The token is a freshly minted agent key, named
// after the client so the dashboard and the activity log show who is connected.
func (w *webApp) token(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(rw, http.StatusBadRequest, "invalid_request", "unparsable form")
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		oauthError(rw, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	ac, ok := w.prov.takeCode(r.FormValue("code"))
	if !ok {
		oauthError(rw, http.StatusBadRequest, "invalid_grant", "unknown, expired, or already-used code")
		return
	}
	if ac.ClientID != r.FormValue("client_id") || ac.RedirectURI != r.FormValue("redirect_uri") {
		oauthError(rw, http.StatusBadRequest, "invalid_grant", "code was issued to a different client or redirect")
		return
	}
	if oauth.CodeChallengeS256(r.FormValue("code_verifier")) != ac.Challenge {
		oauthError(rw, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	name := "agent"
	if c, ok := w.prov.client(ac.ClientID); ok && c.Name != "" {
		name = c.Name
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mintFor(r, name, ac.ClientID)
	if err != nil {
		oauthError(rw, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	log.Printf("[delegent] oauth: issued an access token to %q (key %s) — revoke it in the dashboard", name, row.Prefix)
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"access_token": plaintext,
		"token_type":   "Bearer",
		"scope":        ac.Scope,
	})
}

// mountProvider registers the authorization-server surface on serve's own mux. These paths are
// more specific than the dashboard's "/", so they win; none of them sit behind the dashboard
// guard except /oauth/authorize, which checks the session itself.
func mountProvider(mux *http.ServeMux, w *webApp) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", w.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", w.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", w.authServerMeta)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/", w.authServerMeta)
	mux.HandleFunc("GET /.well-known/openid-configuration", w.authServerMeta)
	mux.HandleFunc("POST /oauth/register", w.registerClient)
	mux.HandleFunc("GET /oauth/authorize", w.authorizePage)
	mux.HandleFunc("POST /oauth/authorize", w.authorizeDecide)
	mux.HandleFunc("POST /oauth/token", w.token)
}

var _ = store.AgentKey{}
