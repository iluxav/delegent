package main

// OAuth acquisition for "Add MCP server" — the interactive half that used to be
// hosted-product-only. Adding a server with no token probes the endpoint: an MCP server that
// wants OAuth answers 401 with a WWW-Authenticate header pointing at its protected-resource
// metadata, which names an authorization server. From there we register a client dynamically,
// send the operator through authorization-code + PKCE in their own browser, seal the token,
// and only then introspect and create the target.
//
// The protocol pieces come from the SDK's oauthex (discovery, metadata, dynamic registration)
// and delegent's own oauth package (PKCE, authorize URL, code exchange). The durable state is
// the store's target-less OAuthPending row, which provision.PromoteOAuthPending turns into a
// real target credential.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// addTTL is how long a half-finished "add server" survives while the operator is off at the
// provider's consent screen.
const addTTL = 15 * time.Minute

// pendingAdd is the half of the wizard OAuth does not carry: which server we were adding.
// Kept in memory — a serve restart mid-flow just means starting the add again.
type pendingAdd struct {
	Name, Slug, Endpoint string
	At                   time.Time
}

// discovery is what the endpoint told us about signing in.
type discovery struct {
	Required                                          bool
	Issuer, AuthEndpoint, TokenEndpoint, Registration string
	Scopes                                            []string
	Resource                                          string // what the server calls itself; the token is requested for this
}

// probeAuth asks the MCP endpoint, unauthenticated, whether it needs OAuth. A 401 carrying
// WWW-Authenticate is the signal; anything else means "no OAuth handshake offered here".
func probeAuth(ctx context.Context, endpoint string) (bool, []string) {
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"delegent","version":"0"}}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		return false, nil
	}
	return true, res.Header.Values("WWW-Authenticate")
}

// wellKnown builds the RFC 8414 / RFC 9728 metadata URLs for an issuer or resource, in the
// order a client should try them: path-aware first, then the plain suffix, then OIDC.
func wellKnown(base, kind string) []string {
	u, err := url.Parse(base)
	if err != nil {
		return nil
	}
	path := strings.TrimSuffix(u.Path, "/")
	origin := u.Scheme + "://" + u.Host
	var out []string
	if path != "" {
		out = append(out, origin+"/.well-known/"+kind+path)
	}
	out = append(out, origin+"/.well-known/"+kind)
	if kind == "oauth-authorization-server" {
		if path != "" {
			out = append(out, origin+"/.well-known/openid-configuration"+path)
		}
		out = append(out, origin+"/.well-known/openid-configuration", strings.TrimSuffix(base, "/")+"/.well-known/openid-configuration")
	}
	return out
}

// discoverOAuth walks the MCP authorization discovery chain: 401 → WWW-Authenticate →
// protected-resource metadata → authorization-server metadata. Every step falls back to the
// conventional well-known location, because plenty of servers omit the header parameter.
func discoverOAuth(ctx context.Context, endpoint string) (*discovery, error) {
	needs, headers := probeAuth(ctx, endpoint)
	if !needs {
		return &discovery{}, nil
	}
	d := &discovery{Required: true}
	client := &http.Client{Timeout: 15 * time.Second}

	// 1. the resource-metadata URL the server advertised, if it advertised one
	var prmURLs []string
	if challenges, err := oauthex.ParseWWWAuthenticate(headers); err == nil {
		for _, c := range challenges {
			if u := c.Params["resource_metadata"]; u != "" {
				prmURLs = append(prmURLs, u)
			}
			if s := c.Params["scope"]; s != "" {
				d.Scopes = strings.Fields(s)
			}
		}
	}
	prmURLs = append(prmURLs, wellKnown(endpoint, "oauth-protected-resource")...)

	// 2. protected-resource metadata names the authorization server
	var issuers []string
	for _, u := range prmURLs {
		prm, err := resourceMetadata(ctx, u, endpoint, client)
		if err != nil || prm == nil {
			continue
		}
		d.Resource = prm.Resource
		issuers = append(issuers, prm.AuthorizationServers...)
		if len(prm.ScopesSupported) > 0 && len(d.Scopes) == 0 {
			d.Scopes = prm.ScopesSupported
		}
		break
	}
	// Some servers skip resource metadata entirely and are their own authorization server.
	if len(issuers) == 0 {
		if u, err := url.Parse(endpoint); err == nil {
			issuers = append(issuers, u.Scheme+"://"+u.Host)
		}
	}

	// 3. authorization-server metadata gives the endpoints we actually drive
	for _, issuer := range issuers {
		for _, mu := range wellKnown(issuer, "oauth-authorization-server") {
			asm, err := oauthex.GetAuthServerMeta(ctx, mu, issuer, client)
			if err != nil || asm == nil {
				continue
			}
			d.Issuer, d.AuthEndpoint, d.TokenEndpoint = asm.Issuer, asm.AuthorizationEndpoint, asm.TokenEndpoint
			d.Registration = asm.RegistrationEndpoint
			if len(d.Scopes) == 0 {
				d.Scopes = asm.ScopesSupported
			}
			return d, nil
		}
	}
	return d, errors.New("the server asks for OAuth but its authorization-server metadata could not be read — add it with a token instead")
}

// resourceMetadata fetches protected-resource metadata for endpoint. RFC 9728 wants the
// document to name the endpoint exactly, but some servers name their origin while serving MCP
// under a path (DigitalOcean: resource https://apps.mcp.digitalocean.com, endpoint …/mcp).
// The origin is accepted too — the document is still the one this server pointed us at, so
// it trusts nothing new — and the name it gives becomes the resource the token is asked for.
func resourceMetadata(ctx context.Context, metaURL, endpoint string, c *http.Client) (*oauthex.ProtectedResourceMetadata, error) {
	prm, err := oauthex.GetProtectedResourceMetadata(ctx, metaURL, endpoint, c)
	if err == nil {
		return prm, nil
	}
	u, perr := url.Parse(endpoint)
	if perr != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	for _, alt := range []string{origin, origin + "/"} {
		if alt == endpoint {
			continue
		}
		if prm, aerr := oauthex.GetProtectedResourceMetadata(ctx, metaURL, alt, c); aerr == nil {
			return prm, nil
		}
	}
	return nil, err
}

// redirectURI is where the provider sends the operator back. It must match what we register.
func (w *webApp) redirectURI() string {
	return "http://" + reachableAddr(w.e.cfg.ListenAddr) + "/oauth/callback"
}

// beginOAuth registers a client (dynamically — an MCP server rarely lets you pre-register),
// parks the PKCE state, and returns the URL to send the operator to.
func (w *webApp) beginOAuth(ctx context.Context, d *discovery, add pendingAdd) (string, error) {
	if d.AuthEndpoint == "" || d.TokenEndpoint == "" {
		return "", errors.New("the authorization server did not publish the endpoints needed to sign in")
	}
	if d.Registration == "" {
		return "", errors.New("this authorization server does not support dynamic client registration — obtain a token yourself and paste it above")
	}
	reg, err := oauthex.RegisterClient(ctx, d.Registration, &oauthex.ClientRegistrationMetadata{
		RedirectURIs:            []string{w.redirectURI()},
		ClientName:              "Delegent",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none", // public client: PKCE is the proof
		Scope:                   strings.Join(d.Scopes, " "),
	}, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		return "", fmt.Errorf("registering with %s failed: %w", d.Issuer, err)
	}

	state := randomToken(16)
	verifier := oauth.NewCodeVerifier(randomBytes(32))
	pend := &store.OAuthPending{
		State: state, AuthEndpoint: d.AuthEndpoint, TokenEndpoint: d.TokenEndpoint,
		ClientID: reg.ClientID, Scopes: strings.Join(d.Scopes, " "),
		RedirectURI: w.redirectURI(), CodeVerifier: verifier, CreatedAt: time.Now().Unix(),
	}
	secrets := secretstore.NewDB(w.e.st, w.e.sealer)
	if reg.ClientSecret != "" {
		ref := "oauth_pending_secret:" + state
		if err := secrets.Put(ctx, ref, reg.ClientSecret); err != nil {
			return "", err
		}
		pend.ClientSecretRef = ref
	}
	if err := w.e.st.PutOAuthPending(ctx, pend); err != nil {
		return "", err
	}
	w.rememberAdd(state, add)

	resource := d.Resource
	if resource == "" {
		resource = add.Endpoint
	}
	return oauth.AuthorizeURL(oauth.AuthorizeInput{
		AuthEndpoint: d.AuthEndpoint, ClientID: reg.ClientID, RedirectURI: w.redirectURI(),
		Scopes: d.Scopes, State: state, CodeChallenge: oauth.CodeChallengeS256(verifier),
		Resource: resource, // RFC 8707: the token is for THIS MCP server
	}), nil
}

func (w *webApp) rememberAdd(state string, add pendingAdd) {
	w.addMu.Lock()
	defer w.addMu.Unlock()
	for s, a := range w.adds { // opportunistic sweep of abandoned wizards
		if time.Since(a.At) > addTTL {
			delete(w.adds, s)
		}
	}
	add.At = time.Now()
	w.adds[state] = add
}

func (w *webApp) takeAdd(state string) (pendingAdd, bool) {
	w.addMu.Lock()
	defer w.addMu.Unlock()
	a, ok := w.adds[state]
	delete(w.adds, state)
	return a, ok && time.Since(a.At) <= addTTL
}

// oauthCallback is where the provider returns the operator. It exchanges the code, seals the
// token, then finishes the original job: introspect the server and create the target.
func (w *webApp) oauthCallback(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	add, ok := w.takeAdd(state)
	if !ok {
		w.oauthFailed(rw, r, "", "That sign-in has expired or was already used. Add the server again.")
		return
	}
	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg = d
		}
		w.oauthFailed(rw, r, add.Name, "The provider refused the sign-in: "+msg)
		return
	}
	ctx := r.Context()
	pend, err := w.e.st.GetOAuthPending(ctx, state)
	if err != nil {
		w.oauthFailed(rw, r, add.Name, "That sign-in is no longer pending.")
		return
	}

	secrets := secretstore.NewDB(w.e.st, w.e.sealer)
	clientSecret := ""
	if pend.ClientSecretRef != "" {
		clientSecret, _ = secrets.Get(ctx, pend.ClientSecretRef)
	}
	ts, err := oauth.ExchangeCode(ctx, oauth.ExchangeInput{
		TokenEndpoint: pend.TokenEndpoint, ClientID: pend.ClientID, ClientSecret: clientSecret,
		Code: q.Get("code"), CodeVerifier: pend.CodeVerifier, RedirectURI: pend.RedirectURI,
		Now: func() int64 { return time.Now().Unix() }, HTTP: &http.Client{Timeout: 20 * time.Second},
	})
	if err != nil {
		w.oauthFailed(rw, r, add.Name, "Exchanging the authorization code failed: "+err.Error())
		return
	}

	// The whole TokenSet is sealed, not just the access token — the gateway refreshes it later.
	sealed, err := ts.MarshalSealed()
	if err != nil {
		w.oauthFailed(rw, r, add.Name, err.Error())
		return
	}
	tokenRef := "oauth_pending:" + state
	if err := secrets.Put(ctx, tokenRef, sealed); err != nil {
		w.oauthFailed(rw, r, add.Name, err.Error())
		return
	}
	pend.TokenRef = tokenRef
	if err := w.e.st.PutOAuthPending(ctx, pend); err != nil {
		w.oauthFailed(rw, r, add.Name, err.Error())
		return
	}

	// Now the original job: look at the server as our newly authorized selves.
	res, err := introspect.Introspect(ctx, add.Endpoint, ts.AccessToken)
	if err != nil {
		w.oauthFailed(rw, r, add.Name, "Signed in, but introspecting the server failed: "+err.Error())
		return
	}
	out, err := provision.CreateTarget(ctx, w.e.st, secrets, provision.CreateTargetInput{
		ID: add.Slug, Name: add.Name, Kind: "mcp", Endpoint: add.Endpoint,
		OAuthHandle: state, Owner: w.e.operator, Tools: provision.FromDraft(res.Tools),
	})
	if err != nil {
		w.oauthFailed(rw, r, add.Name, err.Error())
		return
	}
	w.reg.Invalidate(out.ID)
	http.Redirect(rw, r, "/targets/"+out.ID, http.StatusSeeOther)
}

// oauthFailed puts the operator back on the add form with the reason, rather than a bare error
// page — the flow is interactive, so the recovery has to be too.
func (w *webApp) oauthFailed(rw http.ResponseWriter, r *http.Request, name, msg string) {
	w.page(rw, r, "new", "newTarget", newTargetForm{Name: name, Error: msg})
}
