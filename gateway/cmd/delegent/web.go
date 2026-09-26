package main

// The web dashboard delegent serve hosts at / — htmx + a precompiled Tailwind sheet, embedded,
// so the binary stays self-contained. Same edit cores as the TUI and the CLI (provision,
// registry.Invalidate), so a change made here means exactly what it means everywhere else.

import (
	"bytes"
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"

	"delegent.dev/gateway"
)

//go:embed web/templates/*.html
var webTemplates embed.FS

//go:embed web/static
var webStatic embed.FS

type webApp struct {
	e    *env
	reg  *gateway.Registry
	auth *webAuth
	tpl  *template.Template

	// prov is this gateway acting as its own OAuth authorization server, so an agent can sign
	// in instead of being handed a minted key.
	prov *provider

	// adds holds "add server" wizards that are off at an OAuth provider's consent screen,
	// keyed by the OAuth state. In memory on purpose: a serve restart mid-flow just means
	// starting the add over, and nothing here is a secret.
	addMu sync.Mutex
	adds  map[string]pendingAdd
}

// mountWeb wires the dashboard onto serve's mux. /mcp and /admin patterns are more specific
// than "/", so they keep winning; everything else is the dashboard.
func mountWeb(mux *http.ServeMux, e *env, reg *gateway.Registry) error {
	auth, err := newWebAuth(e)
	if err != nil {
		return err
	}
	tpl, err := template.New("").Funcs(template.FuncMap{
		"join":         strings.Join,
		"lower":        strings.ToLower,
		"time":         evTime,
		"catalogBrand": catalogBrand,
	}).ParseFS(webTemplates, "web/templates/*.html")
	if err != nil {
		return err
	}
	prov, err := newProvider(e.home)
	if err != nil {
		return err
	}
	w := &webApp{e: e, reg: reg, auth: auth, tpl: tpl, prov: prov, adds: map[string]pendingAdd{}}
	mountProvider(mux, w)

	static, _ := fs.Sub(webStatic, "web")
	sub := http.NewServeMux()
	sub.Handle("GET /static/", http.FileServerFS(static))
	sub.HandleFunc("GET /setup", w.setupPage)
	sub.HandleFunc("POST /setup", w.setupSubmit)
	sub.HandleFunc("GET /login", w.loginPage)
	sub.HandleFunc("POST /login", w.loginSubmit)
	sub.HandleFunc("POST /logout", w.logout)

	guarded := http.NewServeMux()
	guarded.HandleFunc("GET /{$}", w.index)
	guarded.HandleFunc("GET /targets", w.targetList)
	guarded.HandleFunc("GET /targets/new", w.newTargetPage)
	guarded.HandleFunc("POST /targets", w.createTarget)
	guarded.HandleFunc("GET /oauth/callback", w.oauthCallback)
	guarded.HandleFunc("GET /targets/{id}", w.targetPage)
	guarded.HandleFunc("POST /targets/{id}/policy", w.savePolicy)
	guarded.HandleFunc("POST /targets/{id}/scopes", w.saveScopes)
	guarded.HandleFunc("POST /targets/{id}/enabled", w.setEnabled)
	guarded.HandleFunc("POST /targets/{id}/remove", w.removeTarget)
	guarded.HandleFunc("POST /targets/{id}/introspect", w.reintrospect)
	guarded.HandleFunc("GET /targets/{id}/audit", w.auditTab)
	guarded.HandleFunc("GET /targets/{id}/audit/rows", w.auditRows)
	guarded.HandleFunc("GET /targets/{id}/consents", w.consentsTab)
	guarded.HandleFunc("GET /targets/{id}/consents/cards", w.consentCards)
	guarded.HandleFunc("GET /consents/live", w.liveConsents)
	guarded.HandleFunc("POST /consents/{id}", w.resolveConsent)
	guarded.HandleFunc("GET /runs", w.runsPage)
	guarded.HandleFunc("GET /runs/{id}", w.runPage)
	guarded.HandleFunc("GET /runs/{id}/diagram", w.runDiagram)
	guarded.HandleFunc("GET /runs/{id}/state", w.runState)
	guarded.HandleFunc("GET /connect", w.connectPane)
	guarded.HandleFunc("GET /keys", w.keysPage)
	guarded.HandleFunc("POST /keys", w.mintKey)
	guarded.HandleFunc("POST /keys/{id}/revoke", w.revokeKey)
	guarded.HandleFunc("POST /keys/{id}/roll", w.rollKey)
	guarded.HandleFunc("POST /keys/{id}/channels", w.setKeyChannels)
	sub.Handle("/", auth.require(guarded))

	mux.Handle("/", sub)
	return nil
}

func (w *webApp) render(rw http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := w.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("dashboard: render %s: %v", name, err)
		http.Error(rw, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(rw)
}

// partial renders a named template to HTML for embedding in the page shell.
func (w *webApp) partial(name string, data any) template.HTML {
	var buf bytes.Buffer
	if err := w.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("dashboard: render %s: %v", name, err)
		return template.HTML("<p class=\"text-bad\">template error: " + template.HTMLEscapeString(err.Error()) + "</p>")
	}
	return template.HTML(buf.String())
}

type pageData struct {
	Targets  []targetRow
	Selected string
	User     string
	Version  string
	Main     template.HTML
	Connect  template.HTML
}

// page answers a request either as the full shell (a normal navigation) or as just the main
// pane (an htmx navigation), so every dashboard URL works both ways — refresh included.
func (w *webApp) page(rw http.ResponseWriter, r *http.Request, selected, mainTpl string, mainData any) {
	main := w.partial(mainTpl, mainData)
	if r.Header.Get("HX-Request") != "" && r.Header.Get("HX-Boosted") == "" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = rw.Write([]byte(main))
		return
	}
	w.render(rw, "page", pageData{
		Targets: w.targetRows(r), Selected: selected, User: w.auth.username(), Version: version,
		Main: main, Connect: w.partial("connect", w.connectView(r, "")),
	})
}

// --- auth pages ---

type authPage struct {
	Error    string
	Username string
	Addr     string
	Next     string // where to land after signing in (an agent's authorize page, usually)
}

func (w *webApp) setupPage(rw http.ResponseWriter, r *http.Request) {
	if w.auth.configured() {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	w.auth.setupCode() // prints the code to the terminal on first visit
	w.render(rw, "setup", authPage{Addr: w.e.cfg.ListenAddr})
}

func (w *webApp) setupSubmit(rw http.ResponseWriter, r *http.Request) {
	if w.auth.configured() {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	if r.FormValue("password") != r.FormValue("confirm") {
		w.render(rw, "setup", authPage{Error: "the passwords do not match", Username: r.FormValue("username")})
		return
	}
	if err := w.auth.completeSetup(r.FormValue("code"), r.FormValue("username"), r.FormValue("password")); err != nil {
		w.render(rw, "setup", authPage{Error: err.Error(), Username: r.FormValue("username")})
		return
	}
	w.auth.issueSession(rw)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *webApp) loginPage(rw http.ResponseWriter, r *http.Request) {
	if !w.auth.configured() {
		http.Redirect(rw, r, "/setup", http.StatusSeeOther)
		return
	}
	w.render(rw, "login", authPage{Next: safeNext(r.URL.Query().Get("next"))})
}

// safeNext keeps ?next= to paths on this server: a bare "/..." that is not "//host", so the
// login form can never be turned into an open redirect.
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	return ""
}

func (w *webApp) loginSubmit(rw http.ResponseWriter, r *http.Request) {
	next := safeNext(r.FormValue("next"))
	if !w.auth.login(r.FormValue("username"), r.FormValue("password")) {
		w.render(rw, "login", authPage{Error: "wrong username or password", Username: r.FormValue("username"), Next: next})
		return
	}
	w.auth.issueSession(rw)
	if next == "" {
		next = "/"
	}
	http.Redirect(rw, r, next, http.StatusSeeOther)
}

func (w *webApp) logout(rw http.ResponseWriter, r *http.Request) {
	w.auth.clearSession(rw)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

// --- index ---

func (w *webApp) index(rw http.ResponseWriter, r *http.Request) {
	targets := w.targetRows(r)
	tools, enabled := 0, 0
	for _, target := range targets {
		tools += target.Tools
		if target.Enabled {
			enabled++
		}
	}
	w.page(rw, r, "", "overview", map[string]any{
		"Targets": targets, "Tools": tools, "Enabled": enabled,
		"Pending": len(w.reg.PendingConsents(w.e.operator)),
	})
}
