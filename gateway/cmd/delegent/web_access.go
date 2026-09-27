package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// callerOption is one row of an agent's exposure checklist (a target it may use; Checked =
// the edge exists), or one agent in a target's derived "seen by" list. Blocked, on the
// exposure list, says the target is locked against every agent, edge or not.
type callerOption struct {
	ID, Label string
	Detail    string // the id when it differs from the name; a kind for the uses list
	Checked   bool
	Blocked   string
}

// rememberedView is one remembered "always" on the target, as the Access tab lists it.
type rememberedView struct {
	CallerID, Caller, Scopes, Reason string
}

// loadAccess fills the Access and Keys tab data on a target view.
func (w *webApp) loadAccess(r *http.Request, v *targetView, t *store.Target) {
	ctx := r.Context()
	v.Audience, v.Uses, v.Consent = t.Audience, t.Uses, t.Consent
	v.Graph = accessGraph(ctx, w.e.st, t)
	edge := func(agent, target string) bool {
		_, err := w.e.st.GetRelation(ctx, agent, target)
		return err == nil
	}
	names := map[string]string{}
	if ts, err := w.e.st.ListTargets(ctx); err == nil {
		sort.Slice(ts, func(i, j int) bool { return ts[i].ID < ts[j].ID })
		for _, o := range ts {
			names[o.ID] = "agent " + o.Name
			if o.ID == t.ID {
				continue
			}
			detail := ""
			if !strings.EqualFold(o.ID, o.Name) {
				detail = o.ID
			}
			if o.Kind == gateway.TargetKindA2A && o.Enabled && store.Visible(ctx, w.e.st, &store.AgentKey{ID: "k", AgentTargetID: o.ID}, t) {
				v.Callers = append(v.Callers, callerOption{ID: o.ID, Label: o.Name, Detail: detail, Checked: true})
			}
			if t.Kind == gateway.TargetKindA2A {
				row := callerOption{ID: o.ID, Label: o.Name, Detail: detail, Checked: edge(t.ID, o.ID)}
				if o.Kind == gateway.TargetKindA2A {
					row.Detail = strings.TrimSpace("agent " + detail)
				} else {
					row.Detail = strings.TrimSpace("MCP server " + detail)
				}
				if o.Audience == store.AudienceHumans {
					row.Blocked = "locked: no agent"
				}
				v.UsesList = append(v.UsesList, row)
			}
		}
	}
	v.Presets = channelPresets()
	if keys, err := w.e.st.ListAgentKeys(ctx, w.e.operator); err == nil {
		for _, k := range keys {
			names[k.ID] = k.Name
			if k.RevokedAt != 0 {
				continue
			}
			if k.AgentTargetID == t.ID {
				v.AgentKeys = append(v.AgentKeys, keyView{
					ID: k.ID, Name: k.Name, Prefix: k.Prefix, LastUsed: lastUsed(k.LastUsedAt),
					Channels: strings.Join(k.ConsentChannels, ","), Hint: presetHint(k.ConsentChannels), Agent: k.AgentTargetID,
				})
			}
		}
	}
	if ps, err := w.e.st.ListRemembered(ctx, "", t.ID); err == nil {
		for _, p := range ps {
			rv := rememberedView{CallerID: p.Caller, Caller: names[p.Caller], Scopes: strings.Join(p.Scopes, ", "), Reason: p.Reason}
			if rv.Caller == "" {
				rv.Caller = p.Caller
			}
			if rv.Scopes == "" {
				rv.Scopes = "every capability"
			}
			v.Remembered = append(v.Remembered, rv)
		}
	}
}

func (w *webApp) accessTab(rw http.ResponseWriter, r *http.Request) {
	v, _, err := w.loadTarget(r, r.PathValue("id"))
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "access"
	w.page(rw, r, v.T.ID, "target", v)
}

// syncEdges makes the relationship edges from agent to each candidate match the ticked set.
func (w *webApp) syncEdges(r *http.Request, agent string, candidates []callerOption, ticked []string) error {
	on := map[string]bool{}
	known := map[string]bool{}
	for _, c := range candidates {
		known[c.ID] = true
	}
	for _, id := range ticked {
		if !known[id] {
			return fmt.Errorf("no target %q", id)
		}
		on[id] = true
	}
	for _, c := range candidates {
		if on[c.ID] == c.Checked {
			continue
		}
		if err := setRelation(r.Context(), w.e.st, agent, c.ID, on[c.ID]); err != nil {
			return err
		}
	}
	return nil
}

// saveAccess stores the target's lock and consent mode. Live: the gateway and every caller's
// tool list rebuild.
func (w *webApp) saveAccess(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, t, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "access"
	if err := r.ParseForm(); err != nil {
		w.withError(rw, r, v, "bad form")
		return
	}
	if err := applyAccess(r.Context(), w.e.st, t, r.FormValue("audience"), t.Uses, r.FormValue("consent")); err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	w.reg.Invalidate(id)
	v, _, _ = w.loadTarget(r, id)
	v.Tab = "access"
	v.Notice = "Access saved: " + audienceLabel(t, seenBy(r.Context(), w.e.st, t)) + "; " + consentLabel(t.Consent) + ". Live now."
	rw.Header().Set("HX-Trigger", "targets")
	w.page(rw, r, id, "target", v)
}

// saveUses stores an agent's caller gate (what it may use) and the ticked targets as edges.
func (w *webApp) saveUses(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, t, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "access"
	if err := r.ParseForm(); err != nil {
		w.withError(rw, r, v, "bad form")
		return
	}
	if err := applyAccess(r.Context(), w.e.st, t, t.Audience, r.FormValue("uses"), t.Consent); err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	if err := w.syncEdges(r, id, v.UsesList, r.Form["uses_targets"]); err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	w.reg.Invalidate(id)
	v, _, _ = w.loadTarget(r, id)
	v.Tab = "access"
	rels, _ := w.e.st.ListRelations(r.Context(), id, "")
	v.Notice = "Saved: " + t.Name + " uses " + usesLabel(t, rels) + ". Live now."
	rw.Header().Set("HX-Trigger", "targets")
	w.page(rw, r, id, "target", v)
}

func (w *webApp) forgetRemembered(rw http.ResponseWriter, r *http.Request) {
	id, caller := r.PathValue("id"), r.PathValue("caller")
	v, _, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "access"
	if err := w.e.st.DeleteRemembered(r.Context(), caller, id); err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	v, _, _ = w.loadTarget(r, id)
	v.Tab = "access"
	v.Notice = "Forgotten. That caller is asked again next time."
	w.page(rw, r, id, "target", v)
}

func (w *webApp) agentKeysTab(rw http.ResponseWriter, r *http.Request) {
	v, _, err := w.loadTarget(r, r.PathValue("id"))
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "keys"
	w.page(rw, r, v.T.ID, "target", v)
}

// mintAgentKey mints a key issued to this agent — the key it presents when it calls other
// targets through the gateway. Shown once, on this tab.
func (w *webApp) mintAgentKey(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, t, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "keys"
	if t.Kind != gateway.TargetKindA2A {
		w.withError(rw, r, v, "only an A2A agent has keys of its own")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "agent:" + t.ID
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	row, plaintext, err := a.mintAgent(r, name, t.ID)
	if err != nil {
		w.withError(rw, r, v, err.Error())
		return
	}
	v, _, _ = w.loadTarget(r, id)
	v.Tab, v.Minted = "keys", plaintext
	v.Notice = fmt.Sprintf("Key %q minted (%s) for %s. Copy it now — it is never shown again.", name, row.Prefix, t.Name)
	w.page(rw, r, id, "target", v)
}

type relationEdge struct {
	Agent, AgentName, Target, TargetName, Effect string
}

func (w *webApp) relationshipsPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := map[string]any{"Graph": accessGraph(ctx, w.e.st, nil)}
	names := map[string]*store.Target{}
	agents, servers := 0, 0
	if ts, err := w.e.st.ListTargets(ctx); err == nil {
		for _, t := range ts {
			names[t.ID] = t
			if t.Kind == gateway.TargetKindA2A && t.Enabled {
				agents++
			} else if t.Enabled {
				servers++
			}
		}
	}
	var edges []relationEdge
	if rels, err := w.e.st.ListRelations(ctx, "", ""); err == nil {
		for _, rel := range rels {
			e := relationEdge{Agent: rel.Agent, AgentName: rel.Agent, Target: rel.Target, TargetName: rel.Target, Effect: "Not in effect: " + rel.Agent + " uses everything"}
			a, ta := names[rel.Agent]
			t, tt := names[rel.Target]
			if ta {
				e.AgentName = a.Name
			}
			if tt {
				e.TargetName = t.Name
			}
			switch {
			case tt && t.Audience == store.AudienceHumans:
				e.Effect = "Not in effect: " + e.TargetName + " is locked against agents"
			case ta && a.Uses == store.UsesListed:
				e.Effect = e.AgentName + " sees " + e.TargetName
			}
			edges = append(edges, e)
		}
	}
	data["Edges"], data["Agents"], data["Servers"] = edges, agents, servers
	w.page(rw, r, "", "relationshipsPage", data)
}
