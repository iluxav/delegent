package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// newDashboard inits a throwaway instance and mounts the dashboard on a test server. The
// returned logs capture what serve would print — including the setup code.
func newDashboard(t *testing.T) (*httptest.Server, *env, *bytes.Buffer) {
	t.Helper()
	t.Setenv("DELEGENT_MASTER_KEY", "")
	home := t.TempDir()
	if err := cmdInit([]string{"--home", home}); err != nil {
		t.Fatal(err)
	}
	e, err := requireOperator(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	mux := http.NewServeMux()
	if err := mountWeb(mux, e, gateway.NewRegistry(e.st, e.sealer)); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, e, &logs
}

func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(res.Body)
	return res.StatusCode, b.String()
}

func post(t *testing.T, c *http.Client, u string, form url.Values, htmx bool) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(res.Body)
	return res, b.String()
}

var codeRE = regexp.MustCompile(`enter this code in the browser: (\d{6})`)

func TestDashboardAuth(t *testing.T) {
	ts, e, logs := newDashboard(t)
	c := browser(t)

	// no .auth yet: everything lands on setup, and visiting it prints the code
	if code, body := get(t, c, ts.URL+"/"); code != 200 || !strings.Contains(body, "Set up the dashboard") {
		t.Fatalf("first visit should be the setup page: %d", code)
	}
	m := codeRE.FindStringSubmatch(logs.String())
	if m == nil {
		t.Fatalf("setup code not printed:\n%s", logs.String())
	}
	setupCode := m[1]

	form := url.Values{"code": {"000000"}, "username": {"ilya"}, "password": {"correct horse"}, "confirm": {"correct horse"}}
	if _, body := post(t, c, ts.URL+"/setup", form, false); !strings.Contains(body, "wrong code") {
		t.Fatal("a wrong code must be rejected")
	}
	form.Set("code", setupCode)
	if res, body := post(t, c, ts.URL+"/setup", form, false); res.Request.URL.Path != "/" || !strings.Contains(body, "Sign out") {
		t.Fatalf("setup should sign in and land on the dashboard: %s", res.Request.URL)
	}
	if _, err := os.Stat(filepath.Join(e.home, authFile)); err != nil {
		t.Fatalf(".auth not written: %v", err)
	}
	if _, body := get(t, c, ts.URL+"/setup"); strings.Contains(body, "Set up the dashboard") {
		t.Fatal("setup must not be offered again once .auth exists")
	}

	// a fresh browser must sign in; wrong password fails; htmx gets a redirect header
	c2 := browser(t)
	if _, body := get(t, c2, ts.URL+"/"); !strings.Contains(body, "Sign in") {
		t.Fatal("no session should land on login")
	}
	if _, body := post(t, c2, ts.URL+"/login", url.Values{"username": {"ilya"}, "password": {"nope"}}, false); !strings.Contains(body, "wrong username or password") {
		t.Fatal("wrong password accepted")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/targets/new", nil)
	req.Header.Set("HX-Request", "true")
	if res, err := c2.Do(req); err != nil || res.StatusCode != 204 || res.Header.Get("HX-Redirect") != "/login" {
		t.Fatalf("htmx without a session should get HX-Redirect to /login: %v %v", res, err)
	}
	if res, body := post(t, c2, ts.URL+"/login", url.Values{"username": {"ilya"}, "password": {"correct horse"}}, false); res.Request.URL.Path != "/" || !strings.Contains(body, "Sign out") {
		t.Fatal("login with the right password should reach the dashboard")
	}

	// the sealed file survives a restart: a new webAuth loads it and the password still works
	again, err := newWebAuth(e)
	if err != nil {
		t.Fatal(err)
	}
	if !again.login("ilya", "correct horse") || again.login("ilya", "wrong") {
		t.Fatal("reloaded .auth does not verify the password correctly")
	}
}

func TestDashboardTargets(t *testing.T) {
	// a fake upstream with one tool, so target add has something to introspect
	type args struct {
		Path string `json:"path"`
	}
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	mcp.AddTool(up, &mcp.Tool{Name: "read_file", Description: "Read a file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: a.Path}}}, nil, nil
		})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil))
	defer upstream.Close()

	ts, _, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	// add: introspects, drafts read_file as files:read, redirects to the target
	res, _ := post(t, c, ts.URL+"/targets", url.Values{"name": {"fake"}, "endpoint": {upstream.URL}}, true)
	if res.StatusCode != 204 || res.Header.Get("HX-Redirect") != "/targets/fake" {
		t.Fatalf("add target: %d %q", res.StatusCode, res.Header.Get("HX-Redirect"))
	}
	if code, body := get(t, c, ts.URL+"/targets/fake"); code != 200 || !strings.Contains(body, "read_file") || !strings.Contains(body, `value="files:read"`) {
		t.Fatalf("target page: %d\n%s", code, body)
	}

	// edit the mapping: read_file becomes a write on files:write
	_, body := post(t, c, ts.URL+"/targets/fake/policy", url.Values{"tool": {"read_file"}, "effect.read_file": {"write"}, "scope.read_file": {"files:write"}}, true)
	if !strings.Contains(body, "Policy saved") || !strings.Contains(body, `value="files:write"`) || !strings.Contains(body, "fx-write") {
		t.Fatalf("policy save:\n%s", body)
	}
	// a classified tool without a scope is refused with a hint, not silently saved
	if _, body := post(t, c, ts.URL+"/targets/fake/policy", url.Values{"tool": {"read_file"}, "effect.read_file": {"read"}, "scope.read_file": {""}}, true); !strings.Contains(body, "needs a scope") {
		t.Fatal("missing scope should be an error")
	}

	// withhold everything but mcp:connect. The entitlement still holds files:read from the
	// first classification — re-classifying unions scopes, never narrows — so it is 1 of 3.
	if _, body := post(t, c, ts.URL+"/targets/fake/scopes", url.Values{"granted": {"mcp:connect"}}, true); !strings.Contains(body, "Scopes saved — 1 of 3") || !strings.Contains(body, "withheld") {
		t.Fatalf("scope save:\n%s", body)
	}
	if _, body := post(t, c, ts.URL+"/targets/fake/enabled", url.Values{"enabled": {"false"}}, true); !strings.Contains(body, "Target disabled") {
		t.Fatal("disable")
	}
	if _, body := post(t, c, ts.URL+"/targets/fake/introspect", url.Values{}, true); !strings.Contains(body, "already covers") {
		t.Fatalf("re-introspect with nothing new:\n%s", body)
	}
	// a full (non-htmx) navigation renders the shell with the sidebar around the same pane
	if _, body := get(t, c, ts.URL+"/targets/fake"); !strings.Contains(body, "<aside") || !strings.Contains(body, "Save policy") {
		t.Fatal("full page should include the shell")
	}
}

func TestDashboardKeysAndSnippets(t *testing.T) {
	ts, _, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	// with no keys the snippets carry the placeholder and say so
	_, body := get(t, c, ts.URL+"/connect")
	if !strings.Contains(body, "No keys yet") || !strings.Contains(body, "dgk_…") {
		t.Fatalf("empty connect pane:\n%s", body)
	}
	for _, want := range []string{"Claude Code", "Claude Desktop", "Cursor", "VS Code", "ChatGPT / OpenAI", "Any HTTP client"} {
		if !strings.Contains(body, want) {
			t.Errorf("connect pane missing the %s snippet", want)
		}
	}

	// a name is required
	if _, body := post(t, c, ts.URL+"/keys", url.Values{"name": {""}}, true); !strings.Contains(body, "give the key a name") {
		t.Error("an unnamed key should be refused")
	}

	// minting shows the plaintext once and bakes it into every snippet
	_, body = post(t, c, ts.URL+"/keys", url.Values{"name": {"laptop"}}, true)
	m := regexp.MustCompile(`(dgk_[A-Za-z0-9_-]{24,})`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no plaintext key in the mint response:\n%s", body)
	}
	key := m[1]
	if !strings.Contains(body, "shown once") || strings.Contains(body, "dgk_…") {
		t.Error("a freshly minted pane should show the real key, not the placeholder")
	}
	// JSON in the page is HTML-escaped (the browser renders it back, and Copy reads
	// textContent), so assert against the text a reader actually sees.
	shown := html.UnescapeString(body)
	if !strings.Contains(shown, `"DELEGENT_AGENT_KEY": "`+key+`"`) {
		t.Error("stdio snippet does not carry the minted key")
	}
	if !strings.Contains(shown, `"Authorization": "Bearer `+key+`"`) {
		t.Error("remote snippet does not carry the minted key")
	}
	if !strings.Contains(shown, `"server_label": "delegent"`) || !strings.Contains(shown, `"servers"`) {
		t.Error("expected the OpenAI and VS Code shapes to differ from the mcpServers one")
	}

	// reloading the pane cannot show a stored key again
	if _, body := get(t, c, ts.URL+"/connect"); strings.Contains(body, key) || !strings.Contains(body, "dgk_…") {
		t.Error("a stored key must never be rendered again")
	}

	// roll: a new key under the same name, the old one revoked
	id := regexp.MustCompile(`/keys/(akey_[^/]+)/roll`).FindStringSubmatch(body)
	if id == nil {
		t.Fatalf("no roll action for the minted key:\n%s", body)
	}
	_, body = post(t, c, ts.URL+"/keys/"+id[1]+"/roll", url.Values{}, true)
	rolled := regexp.MustCompile(`(dgk_[A-Za-z0-9_-]{24,})`).FindStringSubmatch(body)
	if rolled == nil || rolled[1] == key {
		t.Fatal("roll should mint a different key")
	}
	if !strings.Contains(body, "revoked") || !strings.Contains(body, "Rolled") {
		t.Errorf("roll should revoke the old key:\n%s", body)
	}

	// revoke the survivor
	id2 := regexp.MustCompile(`/keys/(akey_[^/]+)/revoke`).FindStringSubmatch(body)
	if id2 == nil {
		t.Fatal("no revoke action")
	}
	if _, body := post(t, c, ts.URL+"/keys/"+id2[1]+"/revoke", url.Values{}, true); !strings.Contains(body, "Key revoked") {
		t.Error("revoke")
	}
}

func TestDashboardTabs(t *testing.T) {
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	mcp.AddTool(up, &mcp.Tool{Name: "read_file", Description: "Read a file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil))
	defer upstream.Close()

	ts, _, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	post(t, c, ts.URL+"/targets", url.Values{"name": {"fake"}, "endpoint": {upstream.URL}}, true)

	// the three tabs are reachable by URL, and each marks itself active
	for _, tc := range []struct{ path, wants string }{
		{"/targets/fake", "Save policy"},
		{"/targets/fake/audit", "Activity"},
		{"/targets/fake/consents", "Waiting on you"},
	} {
		code, body := get(t, c, ts.URL+tc.path)
		if code != 200 || !strings.Contains(body, tc.wants) {
			t.Fatalf("%s: %d, missing %q", tc.path, code, tc.wants)
		}
		if !strings.Contains(body, "mtab-on") {
			t.Errorf("%s: no active tab marked", tc.path)
		}
	}

	// empty states read as empty, not broken
	var body string
	if _, b := get(t, c, ts.URL+"/targets/fake/consents"); !strings.Contains(b, "Nothing waiting") || !strings.Contains(b, "No decisions recorded") {
		t.Error("consents empty state")
	}
	if _, b := get(t, c, ts.URL+"/targets/fake/audit"); !strings.Contains(b, "every event") {
		t.Error("audit filter missing")
	}

	// the pollers skip the swap when nothing moved, so a half-filled form is never clobbered
	_, body = get(t, c, ts.URL+"/targets/fake/audit/rows?known=")
	sig := regexp.MustCompile(`id="akn" name="known" value="([^"]*)"`).FindStringSubmatch(body)
	if sig == nil {
		t.Fatalf("no audit signature:\n%s", body)
	}
	res, _ := c.Get(ts.URL + "/targets/fake/audit/rows?known=" + url.QueryEscape(sig[1]))
	if res.StatusCode != 204 {
		t.Errorf("unchanged audit should be 204, got %d", res.StatusCode)
	}
	res, _ = c.Get(ts.URL + "/targets/fake/consents/cards?known=")
	if res.StatusCode != 200 {
		t.Errorf("first consents poll should render, got %d", res.StatusCode)
	}

	// The dashboard-wide popup must render cleanly with NOTHING waiting. An empty list used to
	// blow up the template, which returns 500, which htmx ignores — leaving a modal you already
	// decided on screen forever.
	// nothing waiting and nothing changed: no swap
	if res, _ := c.Get(ts.URL + "/consents/live?known="); res.StatusCode != 204 {
		t.Errorf("idle popup should be 204, got %d", res.StatusCode)
	}
	// but a browser still showing a decided ask (stale signature) must get an EMPTY popup back,
	// not an error. Rendering an empty list used to blow up the template, which returns 500,
	// which htmx ignores — leaving a modal you already decided on screen forever.
	status, body2 := get(t, c, ts.URL+"/consents/live?known=creq_already_decided")
	if status != 200 {
		t.Fatalf("stale popup should render empty, got %d:\n%s", status, body2)
	}
	if !strings.Contains(body2, `id="pkn"`) || strings.Contains(body2, `hx-post="/consents/`) {
		t.Errorf("stale popup should clear to just the signature:\n%s", body2)
	}

	// resolving an ask that no longer exists explains itself instead of erroring
	if _, body := post(t, c, ts.URL+"/consents/creq_gone", url.Values{"target": {"fake"}, "action": {"approve"}, "scope": {"files:read"}, "ttl": {"60"}}, true); !strings.Contains(body, "no longer live") {
		t.Errorf("stale ask:\n%s", body)
	}
	// approving with nothing ticked is refused rather than minting an empty grant
	if _, body := post(t, c, ts.URL+"/consents/creq_x", url.Values{"target": {"fake"}, "action": {"approve"}, "ttl": {"60"}}, true); !strings.Contains(body, "Tick at least one scope") {
		t.Error("empty approval should be refused")
	}
}

// fakeOAuthServers stands up an MCP server that demands OAuth and the authorization server it
// points at: protected-resource metadata, authorization-server metadata, dynamic registration,
// and a token endpoint. Returns the MCP endpoint URL. hostResource makes the resource metadata
// name the server's origin instead of its /mcp endpoint, the way DigitalOcean's does.
func fakeOAuthServers(t *testing.T, accessToken string, hostResource bool) string {
	t.Helper()
	var asURL, rsURL string

	asMux := http.NewServeMux()
	as := httptest.NewServer(asMux)
	t.Cleanup(as.Close)
	asURL = as.URL
	asMux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": asURL, "authorization_endpoint": asURL + "/authorize",
			"token_endpoint": asURL + "/token", "registration_endpoint": asURL + "/register",
			"jwks_uri": asURL + "/jwks", "response_types_supported": []string{"code"},
			"code_challenge_methods_supported": []string{"S256"},
			"scopes_supported":                 []string{"mcp:read"},
		})
	})
	asMux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"client_id": "dyn-client", "redirect_uris": []string{"http://x/cb"}})
	})
	asMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") == "" || r.Form.Get("code_verifier") == "" {
			t.Errorf("token request missing PKCE/code: %v", r.Form)
		}
		writeJSON(w, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600})
	})

	up := mcp.NewServer(&mcp.Implementation{Name: "secured", Version: "1"}, nil)
	mcp.AddTool(up, &mcp.Tool{Name: "list_things", Description: "List things."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil)

	rsMux := http.NewServeMux()
	rs := httptest.NewServer(rsMux)
	t.Cleanup(rs.Close)
	rsURL = rs.URL
	rsMux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		resource := rsURL + "/mcp"
		if hostResource {
			resource = rsURL
		}
		writeJSON(w, map[string]any{"resource": resource, "authorization_servers": []string{asURL}})
	})
	rsMux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+rsURL+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mcpHandler.ServeHTTP(w, r)
	})
	return rs.URL + "/mcp"
}

// TestDashboardOAuthHostResource: resource metadata that names the server's origin rather than
// its /mcp endpoint still leads to sign-in, and the token is requested for that origin.
func TestDashboardOAuthHostResource(t *testing.T) {
	endpoint := fakeOAuthServers(t, "tok-host", true)
	origin := strings.TrimSuffix(endpoint, "/mcp")
	ts, _, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	res, body := post(t, c, ts.URL+"/targets", url.Values{"name": {"Host Named"}, "endpoint": {endpoint}}, true)
	if res.StatusCode != 204 {
		t.Fatalf("expected a redirect to the provider, got %d:\n%s", res.StatusCode, body)
	}
	authURL, err := url.Parse(res.Header.Get("HX-Redirect"))
	if err != nil || authURL.Path != "/authorize" {
		t.Fatalf("not an authorize URL: %q (%v)", res.Header.Get("HX-Redirect"), err)
	}
	if got := authURL.Query().Get("resource"); got != origin {
		t.Errorf("resource indicator should be what the server calls itself (%q), got %q", origin, got)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// TestDashboardOAuthAdd drives the whole acquisition: adding a protected server with no token
// discovers its authorization server, registers a client, and hands back an authorize URL; the
// provider's callback then exchanges the code and creates the target with a sealed token.
func TestDashboardOAuthAdd(t *testing.T) {
	endpoint := fakeOAuthServers(t, "tok-abc123", false)
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	// no token: the dashboard must discover OAuth and send the operator to the provider
	res, body := post(t, c, ts.URL+"/targets", url.Values{"name": {"Secured Wiki"}, "endpoint": {endpoint}}, true)
	if res.StatusCode != 204 {
		t.Fatalf("expected a redirect to the provider, got %d:\n%s", res.StatusCode, body)
	}
	authURL, err := url.Parse(res.Header.Get("HX-Redirect"))
	if err != nil || authURL.Path != "/authorize" {
		t.Fatalf("not an authorize URL: %q (%v)", res.Header.Get("HX-Redirect"), err)
	}
	q := authURL.Query()
	if q.Get("client_id") != "dyn-client" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL missing dynamic client or PKCE: %v", q)
	}
	if q.Get("resource") != endpoint {
		t.Errorf("resource indicator should bind the token to this server, got %q", q.Get("resource"))
	}
	state := q.Get("state")
	if state == "" {
		t.Fatal("no state")
	}

	// the provider returns the operator with a code; that finishes the add
	cb, cbBody := get(t, c, ts.URL+"/oauth/callback?code=auth-code-1&state="+url.QueryEscape(state))
	if cb != 200 {
		t.Fatalf("callback: %d\n%s", cb, cbBody)
	}
	if !strings.Contains(cbBody, "list_things") {
		t.Fatalf("callback should land on the new target's policy:\n%s", cbBody)
	}

	// the target exists under the slugified name, with an OAuth credential
	tgt, err := e.st.GetTarget(context.Background(), "secured-wiki")
	if err != nil {
		t.Fatalf("target not created under the slug: %v", err)
	}
	if tgt.CredentialKind != "oauth2" || tgt.CredentialRef == "" {
		t.Fatalf("expected a sealed oauth2 credential, got kind=%q ref=%q", tgt.CredentialKind, tgt.CredentialRef)
	}
	if oc, err := e.st.GetOAuthClient(context.Background(), "secured-wiki"); err != nil || oc.ClientID != "dyn-client" {
		t.Fatalf("oauth client row: %+v %v", oc, err)
	}
	// the sealed credential is the whole TokenSet, so the gateway can refresh it later
	raw, err := secretstore.NewDB(e.st, e.sealer).Get(context.Background(), tgt.CredentialRef)
	if err != nil {
		t.Fatalf("credential unreadable: %v", err)
	}
	set, err := oauth.UnmarshalSealed(raw)
	if err != nil || set.AccessToken != "tok-abc123" {
		t.Fatalf("sealed token wrong: %+v %v", set, err)
	}

	// a state cannot be replayed
	if _, body := get(t, c, ts.URL+"/oauth/callback?code=x&state="+url.QueryEscape(state)); !strings.Contains(body, "expired or was already used") {
		t.Error("callback state should be single-use")
	}
}

// newGateway is newDashboard plus the real /mcp endpoint, so a test can play the part of an
// OAuth-speaking agent from the first 401 all the way to a tool call.
func newGateway(t *testing.T) (*httptest.Server, *env, *bytes.Buffer, *gateway.Registry) {
	t.Helper()
	t.Setenv("DELEGENT_MASTER_KEY", "")
	t.Setenv("DELEGENT_AUTH", "")
	home := t.TempDir()
	if err := cmdInit([]string{"--home", home}); err != nil {
		t.Fatal(err)
	}
	e, err := requireOperator(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	reg := gateway.NewRegistry(e.st, e.sealer)
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", reg.ServeAggregate)
	if err := mountWeb(mux, e, reg); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, e, &logs, reg
}

// TestOAuthProvider walks the flow an agent like Claude performs against delegent's own /mcp:
// a 401 that names the metadata, discovery, dynamic registration, the operator approving with
// dashboard credentials, the code exchange, and finally a real MCP call with the issued token.
func TestOAuthProvider(t *testing.T) {
	// something for the agent to actually reach once it is authorized
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	mcp.AddTool(up, &mcp.Tool{Name: "read_file", Description: "Read a file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil))
	defer upstream.Close()

	ts, e, logs, registry := newGateway(t)
	// The gateway holds a live session to the upstream; drop it before the upstream shuts down,
	// or httptest.Server.Close waits forever on that connection.
	defer registry.Invalidate("fake")
	operator := browser(t)
	get(t, operator, ts.URL+"/setup")
	setupCode := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, operator, ts.URL+"/setup", url.Values{"code": {setupCode}, "username": {"ilya"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	post(t, operator, ts.URL+"/targets", url.Values{"name": {"fake"}, "endpoint": {upstream.URL}}, true)

	// 1. the agent calls /mcp with no token and is told where to look
	res, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp should be 401, got %d", res.StatusCode)
	}
	challenge := res.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("401 must point at the resource metadata, got %q", challenge)
	}
	prmURL := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(challenge)[1]

	// 2. protected-resource metadata names this gateway as its own authorization server
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	getJSONInto(t, prmURL, &prm)
	if prm.Resource != ts.URL+"/mcp" {
		t.Fatalf("resource should echo the endpoint, got %q", prm.Resource)
	}
	if len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != ts.URL {
		t.Fatalf("authorization_servers: %v", prm.AuthorizationServers)
	}

	// 3. authorization-server metadata
	var asm struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		RegistrationEndpoint          string   `json:"registration_endpoint"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	getJSONInto(t, prm.AuthorizationServers[0]+"/.well-known/oauth-authorization-server", &asm)
	if asm.Issuer != ts.URL || asm.RegistrationEndpoint == "" || len(asm.CodeChallengeMethodsSupported) == 0 {
		t.Fatalf("authorization server metadata incomplete: %+v", asm)
	}

	// 4. the agent registers itself
	redirect := "http://127.0.0.1:59999/oauth/callback"
	regBody, _ := json.Marshal(map[string]any{"client_name": "Claude", "redirect_uris": []string{redirect}})
	rres, err := http.Post(asm.RegistrationEndpoint, "application/json", bytes.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	defer rres.Body.Close()
	if rres.StatusCode != http.StatusCreated {
		t.Fatalf("registration: %d", rres.StatusCode)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(rres.Body).Decode(&reg); err != nil || reg.ClientID == "" {
		t.Fatalf("no client_id: %v", err)
	}

	// 5. the operator is sent to approve. A signed-out browser must sign in first.
	verifier := oauth.NewCodeVerifier(randomBytes(32))
	authQ := url.Values{
		"client_id": {reg.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {oauth.CodeChallengeS256(verifier)}, "code_challenge_method": {"S256"},
		"state": {"agent-state-1"}, "scope": {"mcp"},
	}
	authURL := asm.AuthorizationEndpoint + "?" + authQ.Encode()
	stranger := browser(t)
	if _, body := get(t, stranger, authURL); !strings.Contains(body, "Sign in") {
		t.Fatal("a signed-out operator must be asked to sign in before approving")
	}
	if _, body := get(t, operator, authURL); !strings.Contains(body, "Claude wants to connect") {
		t.Fatalf("consent screen missing:\n%s", body)
	}

	// 6. Allow → redirected back to the agent with a code
	noFollow := *operator
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	form := url.Values{}
	for k, v := range authQ {
		form[k] = v
	}
	form.Set("action", "allow")
	dres, err := noFollow.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	dres.Body.Close()
	loc, err := url.Parse(dres.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(dres.Header.Get("Location"), redirect) {
		t.Fatalf("should redirect to the agent, got %q", dres.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "agent-state-1" {
		t.Errorf("state not echoed: %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code")
	}

	// 7. the agent exchanges the code (PKCE proves it is the same agent)
	tok := func(verifier, code string) (*http.Response, map[string]any) {
		r, err := http.PostForm(asm.TokenEndpoint, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
			"client_id": {reg.ClientID}, "redirect_uri": {redirect},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r, out
	}
	tres, out := tok(verifier, code)
	if tres.StatusCode != 200 {
		t.Fatalf("token exchange: %d %v", tres.StatusCode, out)
	}
	accessToken, _ := out["access_token"].(string)
	if accessToken == "" || out["token_type"] != "Bearer" {
		t.Fatalf("bad token response: %v", out)
	}
	// the code is single-use
	if again, _ := tok(verifier, code); again.StatusCode == 200 {
		t.Error("an authorization code must not be reusable")
	}

	// 8. the token works on /mcp, and it is a real agent key the operator can see and revoke
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "claude-ish", Version: "0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerRT(accessToken)},
	}, nil)
	if err != nil {
		t.Fatalf("connecting with the issued token failed: %v", err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if !slicesContains(names, "fake__read_file") {
		t.Fatalf("the OAuth session should see the operator's targets, got %v", names)
	}
	keys, _ := e.st.ListAgentKeys(ctx, e.operator)
	var issued *store.AgentKey
	for _, k := range keys {
		if k.Name == "Claude" {
			issued = k
		}
	}
	if issued == nil {
		t.Fatal("the issued token should appear as a revocable key named after the client")
	}
	// It must be distinguishable from a key someone pasted into a config file, because the two
	// are managed differently: a signed-in agent cannot be handed a rolled key.
	if issued.OAuthClientID != reg.ClientID {
		t.Errorf("issued key should record the client it was issued to, got %q", issued.OAuthClientID)
	}

	// the connect pane says so, and offers Disconnect rather than Roll
	_, pane := get(t, operator, ts.URL+"/connect")
	if !strings.Contains(pane, "signed in") || !strings.Contains(pane, "approved for Claude") {
		t.Errorf("pane should mark the signed-in connection:\n%s", pane)
	}
	if !strings.Contains(pane, "Disconnect "+"Claude") && !strings.Contains(pane, ">Disconnect<") {
		t.Errorf("a signed-in agent should offer Disconnect:\n%s", pane)
	}
	if strings.Contains(pane, "/keys/"+issued.ID+"/roll") {
		t.Error("rolling a signed-in agent's key would strand it — Roll must not be offered")
	}

	// PKCE actually gates it: a different verifier must not redeem a code
	form.Set("action", "allow")
	dres2, _ := noFollow.PostForm(ts.URL+"/oauth/authorize", form)
	dres2.Body.Close()
	loc2, _ := url.Parse(dres2.Header.Get("Location"))
	if bad, _ := tok(oauth.NewCodeVerifier(randomBytes(32)), loc2.Query().Get("code")); bad.StatusCode == 200 {
		t.Error("a mismatched PKCE verifier must be rejected")
	}
}

type bearerRT string

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func getJSONInto(t *testing.T, u string, v any) {
	t.Helper()
	res, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("GET %s: %d", u, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", u, err)
	}
}

func slicesContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestDashboardRemoveTarget(t *testing.T) {
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	mcp.AddTool(up, &mcp.Tool{Name: "read_file", Description: "Read a file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, a struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil))
	defer upstream.Close()

	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	post(t, c, ts.URL+"/targets", url.Values{"name": {"fake"}, "endpoint": {upstream.URL}, "credential": {"tok"}}, true)

	ctx := context.Background()
	tgt, err := e.st.GetTarget(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	credRef := tgt.CredentialRef
	if credRef == "" {
		t.Fatal("expected a sealed credential to exist before removal")
	}

	_, body := post(t, c, ts.URL+"/targets/fake/remove", url.Values{}, true)
	if !strings.Contains(body, "fake removed") {
		t.Fatalf("remove should confirm what happened:\n%s", body)
	}

	// the target and everything keyed to it is gone
	if _, err := e.st.GetTarget(ctx, "fake"); !errors.Is(err, store.ErrNotFound) {
		t.Error("target still present")
	}
	if _, err := e.st.GetAdapter(ctx, "fake"); !errors.Is(err, store.ErrNotFound) {
		t.Error("adapter still present")
	}
	if _, err := e.st.GetAdvisor(ctx, "fake"); !errors.Is(err, store.ErrNotFound) {
		t.Error("advisor still present")
	}
	if _, err := e.st.GetEntitlement(ctx, e.operator, "fake"); !errors.Is(err, store.ErrNotFound) {
		t.Error("entitlement still present")
	}
	if _, err := secretstore.NewDB(e.st, e.sealer).Get(ctx, credRef); err == nil {
		t.Error("the sealed credential should be deleted with the target")
	}
	// it is out of the sidebar, and removing it twice is a clean 404 rather than a crash
	if _, body := get(t, c, ts.URL+"/targets"); strings.Contains(body, "/targets/fake\"") {
		t.Error("still listed in the sidebar")
	}
	if _, body := post(t, c, ts.URL+"/targets/fake/remove", url.Values{}, true); !strings.Contains(body, "No target named fake") {
		t.Errorf("removing a gone target should say so:\n%s", body)
	}
}

func TestDashboardConsentChannels(t *testing.T) {
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	_, body := post(t, c, ts.URL+"/keys", url.Values{"name": {"laptop"}}, true)
	id := regexp.MustCompile(`/keys/(akey_[^/]+)/roll`).FindStringSubmatch(body)[1]

	// a fresh key is on auto, and every preset the terminal dashboard offers is offered here
	if !strings.Contains(body, "Ask for consent through") {
		t.Fatalf("no consent-channel picker:\n%s", body)
	}
	for _, want := range []string{"auto", "console only", "in-chat first", "widget first"} {
		if !strings.Contains(body, ">"+want+"<") {
			t.Errorf("preset %q missing from the picker", want)
		}
	}

	ctx := context.Background()
	// set it to in-chat first; console stays the implicit fallback
	_, body = post(t, c, ts.URL+"/keys/"+id+"/channels", url.Values{"channels": {"elicitation,console"}}, true)
	if !strings.Contains(body, "in-chat first") {
		t.Errorf("should confirm the new policy:\n%s", body)
	}
	k, err := e.st.GetAgentKey(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(k.ConsentChannels, ",") != "elicitation,console" {
		t.Fatalf("stored policy: %v", k.ConsentChannels)
	}
	// the picker comes back with that preset selected
	if _, body := get(t, c, ts.URL+"/connect"); !strings.Contains(body, `value="elicitation,console" selected`) {
		t.Errorf("picker should show the stored policy as selected:\n%s", body)
	}

	// back to auto
	post(t, c, ts.URL+"/keys/"+id+"/channels", url.Values{"channels": {""}}, true)
	if k, _ := e.st.GetAgentKey(ctx, id); len(k.ConsentChannels) != 0 {
		t.Errorf("auto should clear the policy, got %v", k.ConsentChannels)
	}

	// an invented channel is refused rather than stored
	_, body = post(t, c, ts.URL+"/keys/"+id+"/channels", url.Values{"channels": {"carrier-pigeon"}}, true)
	if !strings.Contains(body, "unknown consent channel") {
		t.Errorf("bad channel should be refused:\n%s", body)
	}
	if k, _ := e.st.GetAgentKey(ctx, id); len(k.ConsentChannels) != 0 {
		t.Errorf("a refused policy must not be stored, got %v", k.ConsentChannels)
	}
}

func TestDashboardCatalog(t *testing.T) {
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "1"}, nil)
	upstream := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return up }, nil))
	defer upstream.Close()

	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	// every tile posts its endpoint to the ordinary add flow, and its logo is served
	_, body := get(t, c, ts.URL+"/targets/new")
	for _, s := range popularServers {
		if !strings.Contains(body, `value="`+s.Endpoint+`"`) {
			t.Errorf("add page has no tile for %s", s.Name)
		}
		if code, _ := get(t, c, ts.URL+"/static/brands/"+s.ID+".svg"); code != 200 {
			t.Errorf("logo for %s: %d", s.Name, code)
		}
	}
	if strings.Contains(body, "is-added") {
		t.Fatal("nothing is connected yet, so no tile should say Added")
	}

	// a target already on a catalog endpoint turns that tile into a link to it
	post(t, c, ts.URL+"/targets", url.Values{"name": {"work notes"}, "endpoint": {upstream.URL}, "credential": {"tok"}}, true)
	ctx := context.Background()
	tgt, err := e.st.GetTarget(ctx, "work-notes")
	if err != nil {
		t.Fatal(err)
	}
	tgt.Endpoint = popularServers[0].Endpoint
	if err := e.st.PutTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	_, body = get(t, c, ts.URL+"/targets/new")
	if !strings.Contains(body, `href="/targets/work-notes"`) || strings.Contains(body, `value="`+popularServers[0].Endpoint+`"`) {
		t.Fatal("a connected catalog server should link to its target instead of offering sign-in")
	}
}
