package main

// The dashboard-facing half of the /admin surface: targets + policy, entitlement opt-outs,
// keys (mint/revoke/roll), the event log, and the SSE consent stream. Everything here is a
// thin HTTP shell over store/provision/registry calls — the same cores the hosted console
// uses — so the TUI and the console can never disagree about what an edit means.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/oauth"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

// --- targets ---

type targetRow struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Endpoint       string `json:"endpoint"`
	Enabled        bool   `json:"enabled"`
	CredentialKind string `json:"credential_kind"` // "" = static bearer default; "none" when credential-less
	Tools          int    `json:"tools"`
}

type targetDetail struct {
	Target      targetRow            `json:"target"`
	Tools       []provision.ToolSpec `json:"tools"`
	ScopeDocs   []provision.ScopeDoc `json:"scope_docs"`
	Entitlement entitlementView      `json:"entitlement"`
}

type entitlementView struct {
	Scopes    []string `json:"scopes"`
	Disabled  []string `json:"disabled"`
	Effective []string `json:"effective"`
}

func (a *adminEnv) targetRowFor(r *http.Request, t *store.Target) targetRow {
	row := targetRow{ID: t.ID, Name: t.Name, Kind: t.Kind, Endpoint: t.Endpoint, Enabled: t.Enabled, CredentialKind: t.CredentialKind}
	if t.CredentialRef == "" {
		row.CredentialKind = "none"
	}
	if ad, err := a.e.st.GetAdapter(r.Context(), t.AdapterID); err == nil {
		if tools, err := provision.ParseAdapterTools(ad.Doc); err == nil {
			row.Tools = len(tools)
		}
	}
	return row
}

func (a *adminEnv) listTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := a.e.st.ListTargets(r.Context())
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := make([]targetRow, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, a.targetRowFor(r, t))
	}
	adminJSON(w, http.StatusOK, rows)
}

func (a *adminEnv) getTargetDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := a.e.st.GetTarget(ctx, r.PathValue("id"))
	if err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	out := targetDetail{Target: a.targetRowFor(r, t)}
	if ad, err := a.e.st.GetAdapter(ctx, t.AdapterID); err == nil {
		out.Tools, _ = provision.ParseAdapterTools(ad.Doc)
	}
	if t.AdvisorID != "" {
		if av, err := a.e.st.GetAdvisor(ctx, t.AdvisorID); err == nil {
			out.ScopeDocs, _ = provision.ParseAdvisorScopes(av.Doc)
		}
	}
	if ent, err := a.e.st.GetEntitlement(ctx, a.e.operator, t.ID); err == nil {
		out.Entitlement = entitlementView{Scopes: ent.Scopes, Disabled: ent.Disabled, Effective: ent.Effective()}
	}
	adminJSON(w, http.StatusOK, out)
}

type putPolicyReq struct {
	Name  string               `json:"name"`
	Tools []provision.ToolSpec `json:"tools"`
}

func (a *adminEnv) putTargetPolicy(w http.ResponseWriter, r *http.Request) {
	var req putPolicyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	targetID := r.PathValue("id")
	scopes, err := provision.UpdatePolicy(r.Context(), a.e.st, targetID, req.Name, req.Tools)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.notFoundOrErr(w, err)
			return
		}
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.reg.Invalidate(targetID) // live apply: the gateway rebuilds on its next request
	adminJSON(w, http.StatusOK, map[string]any{"scopes": scopes})
}

func (a *adminEnv) setTargetEnabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	ctx := r.Context()
	t, err := a.e.st.GetTarget(ctx, r.PathValue("id"))
	if err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	t.Enabled = req.Enabled
	if err := a.e.st.PutTarget(ctx, t); err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.reg.Invalidate(t.ID)
	adminJSON(w, http.StatusOK, map[string]bool{"enabled": t.Enabled})
}

// introspectTarget re-probes the upstream server and returns the drafted classification —
// the TUI merges rows the stored adapter doesn't know yet as NEW. Uses the target's own
// credential (unsealed just for the probe).
func (a *adminEnv) introspectTarget(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := a.e.st.GetTarget(ctx, r.PathValue("id"))
	if err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	cred := ""
	if t.CredentialRef != "" {
		secrets := secretstore.NewDB(a.e.st, a.e.sealer)
		raw, err := secrets.Get(ctx, t.CredentialRef)
		if err != nil {
			adminJSON(w, http.StatusInternalServerError, map[string]string{"error": "credential unavailable: " + err.Error()})
			return
		}
		cred = raw
		if t.CredentialKind == "oauth2" {
			if ts, err := oauth.UnmarshalSealed(raw); err == nil {
				cred = ts.AccessToken
			}
		}
	}
	res, err := introspect.Introspect(ctx, t.Endpoint, cred)
	if err != nil {
		adminJSON(w, http.StatusBadGateway, map[string]string{"error": "introspection failed: " + err.Error()})
		return
	}
	adminJSON(w, http.StatusOK, res)
}

// --- entitlements (the operator's per-target scope opt-outs) ---

func (a *adminEnv) putEntitlement(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled []string `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	ctx := r.Context()
	targetID := r.PathValue("target")
	ent, err := a.e.st.GetEntitlement(ctx, a.e.operator, targetID)
	if err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	// clamp: only scopes actually held can be opted out — unknown names are dropped silently
	held := map[string]bool{}
	for _, sc := range ent.Scopes {
		held[sc] = true
	}
	disabled := req.Disabled[:0:0]
	for _, sc := range req.Disabled {
		if held[sc] {
			disabled = append(disabled, sc)
		}
	}
	before := ent.Disabled
	ent.Disabled = disabled
	if err := a.e.st.PutEntitlement(ctx, ent); err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	emitScopeToggleEvents(ctx, a.e.st, a.e.operator, targetID, before, disabled)
	a.reg.Invalidate(targetID)
	adminJSON(w, http.StatusOK, entitlementView{Scopes: ent.Scopes, Disabled: ent.Disabled, Effective: ent.Effective()})
}

// emitScopeToggleEvents records one activity-log event per changed opt-out — the same
// scope_enabled/scope_disabled rows the hosted console writes, so the audit trail reads
// identically wherever the toggle happened. Best-effort: a log failure never fails the toggle.
func emitScopeToggleEvents(ctx context.Context, st store.Store, userID, targetID string, before, after []string) {
	was := map[string]bool{}
	for _, sc := range before {
		was[sc] = true
	}
	now := map[string]bool{}
	for _, sc := range after {
		now[sc] = true
	}
	emit := func(evType, scope string) {
		if err := st.AppendEvent(ctx, &store.Event{
			ID: id.New("evt"), CreatedAt: nowMillis(), Type: evType, UserID: userID, TargetID: targetID,
			Scopes: []string{scope}, Decision: "operator", Reason: "operator toggled " + scope,
		}); err != nil {
			log.Printf("dashboard: activity-log append failed (%s): %v", evType, err)
		}
	}
	for sc := range now {
		if !was[sc] {
			emit("scope_disabled", sc)
		}
	}
	for sc := range was {
		if !now[sc] {
			emit("scope_enabled", sc)
		}
	}
}

// --- keys ---

type keyRow struct {
	ID         string `json:"id"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
	RevokedAt  int64  `json:"revoked_at"`
	// ConsentChannels is the key's ordered consent-channel policy (empty = auto); the gateway
	// always falls back to the console after the list.
	ConsentChannels []string `json:"consent_channels,omitempty"`
}

// knownConsentChannels is the closed set a key policy may name — the same set the hosted
// console enforces.
var knownConsentChannels = map[string]bool{"elicitation": true, "widget": true, "console": true}

func validateChannels(channels []string) error {
	for _, c := range channels {
		if !knownConsentChannels[c] {
			return fmt.Errorf("unknown consent channel %q (want elicitation|widget|console)", c)
		}
	}
	return nil
}

// setKeyChannels replaces the key's consent-channel policy (empty = auto).
func (a *adminEnv) setKeyChannels(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConsentChannels []string `json:"consent_channels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := validateChannels(req.ConsentChannels); err != nil {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.e.st.SetAgentKeyConsentChannels(r.Context(), r.PathValue("id"), req.ConsentChannels); err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	adminJSON(w, http.StatusOK, map[string]any{"consent_channels": req.ConsentChannels})
}

func (a *adminEnv) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.e.st.ListAgentKeys(r.Context(), a.e.operator)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	rows := make([]keyRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, keyRow{ID: k.ID, Prefix: k.Prefix, Name: k.Name, CreatedAt: k.CreatedAt,
			LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt, ConsentChannels: k.ConsentChannels})
	}
	adminJSON(w, http.StatusOK, rows)
}

func (a *adminEnv) mintKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	row, plaintext, err := a.mint(r, req.Name)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	adminJSON(w, http.StatusCreated, map[string]any{"key": row, "plaintext": plaintext})
}

func (a *adminEnv) mint(r *http.Request, name string) (keyRow, string, error) {
	full, hash, prefix := agentkey.New()
	k := &store.AgentKey{ID: id.New("akey"), UserID: a.e.operator, Hash: hash, Prefix: prefix, Name: name, CreatedAt: nowMillis()}
	if err := a.e.st.PutAgentKey(r.Context(), k); err != nil {
		return keyRow{}, "", err
	}
	return keyRow{ID: k.ID, Prefix: k.Prefix, Name: k.Name, CreatedAt: k.CreatedAt}, full, nil
}

func (a *adminEnv) revokeKey(w http.ResponseWriter, r *http.Request) {
	if err := a.e.st.RevokeAgentKey(r.Context(), r.PathValue("id"), nowMillis()); err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	adminJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// rollKey mints a NEW key under the old key's name, then revokes the old one — the durable
// name-based event aggregation survives the roll. Mint-then-revoke order: a roll can never
// leave the operator with zero working keys.
func (a *adminEnv) rollKey(w http.ResponseWriter, r *http.Request) {
	old, err := a.e.st.GetAgentKey(r.Context(), r.PathValue("id"))
	if err != nil {
		a.notFoundOrErr(w, err)
		return
	}
	if old.RevokedAt != 0 {
		adminJSON(w, http.StatusBadRequest, map[string]string{"error": "key is already revoked — mint a new one instead"})
		return
	}
	row, plaintext, err := a.mint(r, old.Name)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := a.e.st.RevokeAgentKey(r.Context(), old.ID, nowMillis()); err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("new key minted (%s) but revoking the old failed: %v", row.ID, err)})
		return
	}
	adminJSON(w, http.StatusOK, map[string]any{"key": row, "plaintext": plaintext, "revoked": old.ID})
}

// --- events (audit log) ---

func (a *adminEnv) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	f := store.EventFilter{
		UserID:   a.e.operator,
		KeyName:  q.Get("key_name"),
		Type:     q.Get("type"),
		TargetID: q.Get("target"),
		Tool:     q.Get("tool"),
		Decision: q.Get("decision"),
		Limit:    limit,
	}
	events, err := a.e.st.ListEvents(r.Context(), f)
	if err != nil {
		adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	adminJSON(w, http.StatusOK, events)
}

// --- consent stream (SSE) ---

// streamConsents relays the registry's consent hub as Server-Sent Events: one `data:` line
// per park/resolve event, a comment ping every 25s so proxies and clients notice a dead
// stream. The client re-lists on connect — the stream is deltas, not state.
func (a *adminEnv) streamConsents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		adminJSON(w, http.StatusNotImplemented, map[string]string{"error": "streaming unsupported"})
		return
	}
	events, cancel := a.reg.SubscribeConsent()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()

	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.Owner != "" && ev.Owner != a.e.operator {
				continue
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			fl.Flush()
		}
	}
}

func (a *adminEnv) notFoundOrErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		adminJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	adminJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
