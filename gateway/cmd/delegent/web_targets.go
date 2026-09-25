package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"delegent.dev/gateway"
	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// effects is the closed set the classifier understands, in the order the select shows them.
var effects = []string{"unknown", "read", "write", "destructive", "external", "spends"}

// targetRows is the sidebar list: same row shape the admin API returns.
func (w *webApp) targetRows(r *http.Request) []targetRow {
	ctx := r.Context()
	ts, err := w.e.st.ListTargets(ctx)
	if err != nil {
		return nil
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	rows := make([]targetRow, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, a.targetRowFor(r, t))
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return rows
}

func (w *webApp) targetList(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, "sidebarTargets", pageData{Targets: w.targetRows(r), Selected: r.URL.Query().Get("s")})
}

// toolRow is one editable line of a target's policy. New marks a tool the last re-introspect
// found upstream that the stored policy does not know yet — it exists only until saved.
type toolRow struct {
	provision.ToolSpec
	New bool
}

// scopeRow is one scope the operator's entitlement holds, with what it means and unlocks.
type scopeRow struct {
	Scope   string
	Human   string
	Risk    string
	Tools   []string
	Granted bool
}

type targetView struct {
	T   targetRow
	Tab string // adapter | audit | consents

	// adapter tab
	Tools     []toolRow
	Scopes    []scopeRow
	Unknown   int
	NewCount  int
	Effects   []string
	AllScopes []string

	// audit tab
	Events     []eventView
	EventTypes []string
	FilterType string
	AuditSig   string

	// consents tab
	Live       []gateway.PendingView
	History    []*store.ConsentRequest
	ConsentSig string
	LiveCount  int

	Notice string
	Error  string
}

// loadTarget builds the detail view from the stored adapter, advisor, and entitlement.
func (w *webApp) loadTarget(r *http.Request, id string) (*targetView, *store.Target, error) {
	ctx := r.Context()
	t, err := w.e.st.GetTarget(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	v := &targetView{T: a.targetRowFor(r, t), Effects: effects, Tab: "adapter"}
	// the tab bar shows a badge when an agent is blocked on this target right now
	for _, p := range w.reg.PendingConsents(w.e.operator) {
		if p.TargetID == t.ID {
			v.LiveCount++
		}
	}

	var tools []provision.ToolSpec
	if ad, err := w.e.st.GetAdapter(ctx, t.AdapterID); err == nil {
		tools, _ = provision.ParseAdapterTools(ad.Doc)
	}
	docs := map[string]provision.ScopeDoc{}
	if t.AdvisorID != "" {
		if av, err := w.e.st.GetAdvisor(ctx, t.AdvisorID); err == nil {
			if sd, err := provision.ParseAdvisorScopes(av.Doc); err == nil {
				for _, d := range sd {
					docs[d.Scope] = d
				}
			}
		}
	}
	byScope := map[string][]string{}
	scopeSet := map[string]bool{}
	for _, tool := range tools {
		v.Tools = append(v.Tools, toolRow{ToolSpec: tool})
		if provision.IsUnknown(tool.Effect) {
			v.Unknown++
		}
		if tool.Scope != "" {
			byScope[tool.Scope] = append(byScope[tool.Scope], tool.Name)
			scopeSet[tool.Scope] = true
		}
	}
	v.AllScopes = provision.SortedKeys(scopeSet)

	if ent, err := w.e.st.GetEntitlement(ctx, w.e.operator, t.ID); err == nil {
		off := map[string]bool{}
		for _, sc := range ent.Disabled {
			off[sc] = true
		}
		for _, sc := range ent.Scopes {
			row := scopeRow{Scope: sc, Tools: byScope[sc], Granted: !off[sc]}
			if d, ok := docs[sc]; ok {
				row.Human, row.Risk = d.Human, d.Risk
			}
			v.Scopes = append(v.Scopes, row)
		}
		sort.Slice(v.Scopes, func(i, j int) bool { return v.Scopes[i].Scope < v.Scopes[j].Scope })
	}
	return v, t, nil
}

func (w *webApp) targetPage(rw http.ResponseWriter, r *http.Request) {
	v, _, err := w.loadTarget(r, r.PathValue("id"))
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	w.page(rw, r, v.T.ID, "target", v)
}

func (w *webApp) notFound(rw http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		w.page(rw, r, "", "empty", map[string]any{"Missing": r.PathValue("id")})
		return
	}
	http.Error(rw, err.Error(), http.StatusInternalServerError)
}

// savePolicy rebuilds the target's classification from the edited rows. Effect and scope come
// from the form; description and semantics are kept from the stored policy (or, for a row a
// re-introspect just added, from the hidden fields the form carried).
func (w *webApp) savePolicy(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, _, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.withError(rw, r, v, "bad form")
		return
	}
	stored := map[string]provision.ToolSpec{}
	for _, t := range v.Tools {
		stored[t.Name] = t.ToolSpec
	}
	var tools []provision.ToolSpec
	for _, name := range r.Form["tool"] {
		spec, ok := stored[name]
		if !ok {
			spec = provision.ToolSpec{Name: name, Description: r.FormValue("desc." + name)}
		}
		spec.Effect = r.FormValue("effect." + name)
		spec.Scope = strings.TrimSpace(r.FormValue("scope." + name))
		if provision.IsUnknown(spec.Effect) {
			spec.Effect = "unknown"
		} else if spec.Scope == "" {
			w.withError(rw, r, v, fmt.Sprintf("%s: a %s tool needs a scope (for example %s)", name, spec.Effect, defaultScope(spec.Effect)))
			return
		}
		tools = append(tools, spec)
	}
	scopes, err := provision.UpdatePolicy(r.Context(), w.e.st, id, "", tools)
	if err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	w.reg.Invalidate(id) // live: the gateway rebuilds on its next request
	v, _, _ = w.loadTarget(r, id)
	v.Notice = fmt.Sprintf("Policy saved — %d tools, scopes: %s. Live now.", len(tools), strings.Join(scopes, " "))
	rw.Header().Set("HX-Trigger", "targets")
	w.page(rw, r, id, "target", v)
}

// defaultScope suggests a scope name for the error hint.
func defaultScope(effect string) string {
	switch effect {
	case "read":
		return "data:read"
	case "spends":
		return "billing:spend"
	case "external":
		return "messaging:send"
	}
	return "data:write"
}

// saveScopes stores the operator's opt-outs: every held scope not ticked becomes Disabled.
func (w *webApp) saveScopes(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, _, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.withError(rw, r, v, "bad form")
		return
	}
	ctx := r.Context()
	ent, err := w.e.st.GetEntitlement(ctx, w.e.operator, id)
	if err != nil {
		w.withError(rw, r, v, "no entitlement for this target")
		return
	}
	granted := map[string]bool{}
	for _, sc := range r.Form["granted"] {
		granted[sc] = true
	}
	var disabled []string
	for _, sc := range ent.Scopes {
		if !granted[sc] {
			disabled = append(disabled, sc)
		}
	}
	before := ent.Disabled
	ent.Disabled = disabled
	if err := w.e.st.PutEntitlement(ctx, ent); err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	emitScopeToggleEvents(ctx, w.e.st, w.e.operator, id, before, disabled)
	w.reg.Invalidate(id)
	v, _, _ = w.loadTarget(r, id)
	v.Notice = fmt.Sprintf("Scopes saved — %d of %d grantable. Live now.", len(ent.Scopes)-len(disabled), len(ent.Scopes))
	w.page(rw, r, id, "target", v)
}

func (w *webApp) setEnabled(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	t, err := w.e.st.GetTarget(ctx, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	t.Enabled = r.FormValue("enabled") == "true"
	if err := w.e.st.PutTarget(ctx, t); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.reg.Invalidate(id)
	v, _, _ := w.loadTarget(r, id)
	if t.Enabled {
		v.Notice = "Target enabled — agents see its tools again."
	} else {
		v.Notice = "Target disabled — its tools are gone from every agent's list until re-enabled."
	}
	rw.Header().Set("HX-Trigger", "targets")
	w.page(rw, r, id, "target", v)
}

// reintrospect probes the upstream again and merges tools the stored policy does not know as
// NEW rows, drafted the same way target add drafts them. Nothing persists until Save.
func (w *webApp) reintrospect(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, t, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	res, err := probeUpstream(r.Context(), w.e, t)
	if err != nil {
		w.withError(rw, r, v, "introspection failed: "+err.Error())
		return
	}
	known := map[string]bool{}
	for _, tool := range v.Tools {
		known[tool.Name] = true
	}
	for _, d := range provision.FromDraft(res.Tools) {
		if !known[d.Name] {
			v.Tools = append(v.Tools, toolRow{ToolSpec: d, New: true})
			v.NewCount++
		}
	}
	sort.SliceStable(v.Tools, func(i, j int) bool { return v.Tools[i].Name < v.Tools[j].Name })
	switch v.NewCount {
	case 0:
		v.Notice = fmt.Sprintf("Upstream lists %d tools; the policy already covers all of them.", len(res.Tools))
	default:
		v.Notice = fmt.Sprintf("Upstream lists %d tools, %d not in the policy yet — review the drafted rows and save.", len(res.Tools), v.NewCount)
	}
	w.page(rw, r, id, "target", v)
}

// probeUpstream introspects a stored target with its own credential (unsealed just for the
// probe). Shared by the dashboard and the admin API.
func probeUpstream(ctx context.Context, e *env, t *store.Target) (*introspect.Result, error) {
	cred := ""
	if t.CredentialRef != "" {
		secrets := secretstore.NewDB(e.st, e.sealer)
		raw, err := secrets.Get(ctx, t.CredentialRef)
		if err != nil {
			return nil, fmt.Errorf("credential unavailable: %w", err)
		}
		cred = raw
		if t.CredentialKind == "oauth2" {
			if ts, err := oauth.UnmarshalSealed(raw); err == nil {
				cred = ts.AccessToken
			}
		}
	}
	if t.Kind == gateway.TargetKindA2A {
		res, _, err := a2a.Introspect(ctx, t.Endpoint, cred)
		return res, err
	}
	return introspect.Introspect(ctx, t.Endpoint, cred)
}

func (w *webApp) withError(rw http.ResponseWriter, r *http.Request, v *targetView, msg string) {
	v.Error = msg
	w.page(rw, r, v.T.ID, "target", v)
}

// --- add a target ---

type newTargetForm struct {
	Name, Endpoint string
	Error          string
	Catalog        []catalogTile
}

func (w *webApp) newTargetPage(rw http.ResponseWriter, r *http.Request) {
	w.page(rw, r, "new", "newTarget", newTargetForm{Catalog: w.catalogTiles(r)})
}

// createTarget is target add: introspect the endpoint, accept the drafted classification, and
// provision adapter, advisor, sealed credential, target, and entitlement in one go. The
// gateway picks the new target up live.
// createTarget adds a server. The id is the slugified name — one fewer thing to invent, and
// it is only ever a namespace prefix. With no token, the endpoint is asked whether it wants
// OAuth; if it does, the operator is sent through sign-in and the target is created by the
// callback instead.
func (w *webApp) createTarget(rw http.ResponseWriter, r *http.Request) {
	f := newTargetForm{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Endpoint: strings.TrimSpace(r.FormValue("endpoint")),
	}
	cred := strings.TrimSpace(r.FormValue("credential"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if kind == "" {
		kind = "mcp"
	}
	if f.Name == "" || f.Endpoint == "" {
		w.addFailed(rw, r, f, "a name and an endpoint are required")
		return
	}
	slug := provision.Slug(f.Name)
	if slug == "" {
		w.addFailed(rw, r, f, "that name has no letters or digits to build an id from")
		return
	}
	ctx := r.Context()
	if _, err := w.e.st.GetTarget(ctx, slug); err == nil {
		w.addFailed(rw, r, f, fmt.Sprintf("a server called %q (id %s) already exists — pick another name", f.Name, slug))
		return
	}

	// An agent: read its card, draft its skills, no OAuth discovery (the card declares auth).
	if kind == gateway.TargetKindA2A {
		res, card, err := a2a.Introspect(ctx, f.Endpoint, cred)
		if err != nil {
			w.addFailed(rw, r, f, "could not read the agent card (is the agent up, and does it publish "+a2a.WellKnownPath+"?): "+err.Error())
			return
		}
		out, err := provision.CreateTarget(ctx, w.e.st, secretstore.NewDB(w.e.st, w.e.sealer), provision.CreateTargetInput{
			ID: slug, Name: f.Name, Kind: kind, Endpoint: f.Endpoint, Credential: cred,
			Owner: w.e.operator, Tools: provision.FromDraft(res.Tools),
		})
		if err != nil {
			w.addFailed(rw, r, f, err.Error())
			return
		}
		log.Printf("[delegent] dashboard: added agent %q (%s): %d skill(s)", card.Name, out.ID, len(card.Skills))
		w.reg.Invalidate(out.ID)
		if r.Header.Get("HX-Request") != "" {
			rw.Header().Set("HX-Redirect", "/targets/"+out.ID)
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(rw, r, "/targets/"+out.ID, http.StatusSeeOther)
		return
	}

	// No token: find out whether this server wants a sign-in before assuming it is public.
	if cred == "" {
		d, derr := discoverOAuth(ctx, f.Endpoint)
		if d != nil && d.Required {
			if derr != nil {
				w.addFailed(rw, r, f, derr.Error())
				return
			}
			authURL, err := w.beginOAuth(ctx, d, pendingAdd{Name: f.Name, Slug: slug, Endpoint: f.Endpoint})
			if err != nil {
				w.addFailed(rw, r, f, err.Error())
				return
			}
			log.Printf("[delegent] dashboard: %s needs OAuth — sending the operator to %s", f.Endpoint, d.Issuer)
			if r.Header.Get("HX-Request") != "" {
				rw.Header().Set("HX-Redirect", authURL)
				rw.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(rw, r, authURL, http.StatusSeeOther)
			return
		}
	}

	res, err := introspect.Introspect(ctx, f.Endpoint, cred)
	if err != nil {
		msg := "could not introspect the endpoint (is it reachable, and is the credential valid?): " + err.Error()
		if cred == "" && strings.Contains(err.Error(), "Unauthorized") {
			msg = "the server wants a token and none was given — expand “Use an access token” below and paste it, then try again"
		}
		w.addFailed(rw, r, f, msg)
		return
	}
	out, err := provision.CreateTarget(ctx, w.e.st, secretstore.NewDB(w.e.st, w.e.sealer), provision.CreateTargetInput{
		ID: slug, Name: f.Name, Kind: "mcp", Endpoint: f.Endpoint, Credential: cred,
		Owner: w.e.operator, Tools: provision.FromDraft(res.Tools),
	})
	if err != nil {
		w.addFailed(rw, r, f, err.Error())
		return
	}
	w.reg.Invalidate(out.ID)
	if r.Header.Get("HX-Request") != "" {
		rw.Header().Set("HX-Redirect", "/targets/"+out.ID)
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(rw, r, "/targets/"+out.ID, http.StatusSeeOther)
}

// removeTarget deletes a server and everything scoped to it, then drops it from the live
// gateway. The audit trail stays: what agents did through it is still in the activity log.
func (w *webApp) removeTarget(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := w.e.st.GetTarget(r.Context(), id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	if err := provision.DeleteTarget(r.Context(), w.e.st, secretstore.NewDB(w.e.st, w.e.sealer), id); err != nil {
		v, _, lerr := w.loadTarget(r, id)
		if lerr != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		w.withError(rw, r, v, "could not remove it: "+err.Error())
		return
	}
	w.reg.Invalidate(id)
	log.Printf("[delegent] dashboard: removed target %q (%s)", t.Name, id)
	rw.Header().Set("HX-Trigger", "targets")
	w.page(rw, r, "", "empty", map[string]any{
		"Count": len(w.targetRows(r)),
		"Gone":  t.Name,
	})
}

func (w *webApp) addFailed(rw http.ResponseWriter, r *http.Request, f newTargetForm, msg string) {
	f.Error = msg
	f.Catalog = w.catalogTiles(r)
	w.page(rw, r, "new", "newTarget", f)
}
