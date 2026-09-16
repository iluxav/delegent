package main

// The central pane's Audit and Consents tabs. Adapter (the policy editor) lives in
// web_targets.go. Both tabs here are read-mostly views over the same stores the TUI reads,
// plus the one write that matters: resolving a consent ask.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// eventView is one activity-log row, flattened for the template.
type eventView struct {
	Time, Type, Tool, Scopes, Decision, Reason, Intent, Agent, Error string
	Tone                                                             string // ok | bad | warn | ""
}

// auditTypes is the filter dropdown, in the order a call actually happens.
var auditTypes = []string{
	store.EventConnection, store.EventToolCall, store.EventPermissionRequested,
	store.EventPermissionGranted, store.EventPermissionDenied, store.EventToolResponse,
	store.EventError, store.EventDisconnected,
}

func evTime(ms int64) string {
	t := time.UnixMilli(ms)
	if time.Since(t) < 12*time.Hour {
		return t.Format("15:04:05")
	}
	return t.Format("Jan 2 15:04")
}

func evTone(typ string) string {
	switch typ {
	case store.EventPermissionGranted:
		return "ok"
	case store.EventPermissionDenied, store.EventError:
		return "bad"
	case store.EventPermissionRequested:
		return "warn"
	}
	return ""
}

// events loads this target's activity log, newest first, with a signature the poller uses to
// skip a swap when nothing has changed.
func (w *webApp) events(r *http.Request, targetID, typ string) ([]eventView, string) {
	rows, err := w.e.st.ListEvents(r.Context(), store.EventFilter{
		UserID: w.e.operator, TargetID: targetID, Type: typ, Limit: 200,
	})
	if err != nil || len(rows) == 0 {
		return nil, "empty"
	}
	out := make([]eventView, 0, len(rows))
	for _, e := range rows {
		out = append(out, eventView{
			Time: evTime(e.CreatedAt), Type: e.Type, Tool: e.Tool, Scopes: strings.Join(e.Scopes, " "),
			Decision: e.Decision, Reason: e.Reason, Intent: e.Intent, Agent: e.AgentName,
			Error: e.Error, Tone: evTone(e.Type),
		})
	}
	return out, fmt.Sprintf("%d:%s", len(rows), rows[0].ID)
}

// consents splits this target's asks into the live ones (an agent is blocked on them right
// now) and the decided history, with a signature for the poller.
// except drops an ask that was just decided: ResolvePending signals the blocked goroutine,
// which clears the record a moment later, so a re-render immediately after a decision would
// otherwise still show the ask you just resolved.
func (w *webApp) consents(targetID, except string) (live []gateway.PendingView, history []*store.ConsentRequest, sig string) {
	for _, p := range w.reg.PendingConsents(w.e.operator) {
		if p.TargetID == targetID && p.ID != except {
			live = append(live, p)
		}
	}
	rows, err := w.reg.ListConsentRequests(w.e.operator, true)
	if err == nil {
		for _, c := range rows {
			if c.TargetID == targetID {
				history = append(history, c)
			}
		}
	}
	var b strings.Builder
	for _, p := range live {
		b.WriteString(p.ID)
		b.WriteByte(',')
	}
	b.WriteString("|")
	for _, c := range history {
		b.WriteString(c.ID + ":" + c.Status + ",")
	}
	return live, history, b.String()
}

// allLive is every ask waiting on this operator, across all targets, with a signature for
// the poller. The popup uses it so a blocked agent reaches you wherever you are.
func (w *webApp) allLive(except string) (live []gateway.PendingView, sig string) {
	for _, p := range w.reg.PendingConsents(w.e.operator) {
		if p.ID != except {
			live = append(live, p)
		}
	}
	var b strings.Builder
	for _, p := range live {
		b.WriteString(p.ID)
		b.WriteByte(',')
	}
	return live, b.String()
}

// liveConsents drives the dashboard-wide popup. It returns 204 when the waiting set has not
// changed, so a decision form you are filling in is never swapped out from under you. On the
// Consents tab the popup stays out of the way — that tab already shows the same asks.
func (w *webApp) liveConsents(rw http.ResponseWriter, r *http.Request) {
	live, sig := w.allLive("")
	if strings.Contains(r.Header.Get("HX-Current-URL"), "/consents") {
		live = nil
	}
	if sig == r.URL.Query().Get("known") {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	w.render(rw, "consentPopup", &targetView{Live: live, ConsentSig: sig})
}

// --- tab handlers ---

func (w *webApp) auditTab(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, _, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "audit"
	v.FilterType = r.URL.Query().Get("type")
	v.EventTypes = auditTypes
	v.Events, v.AuditSig = w.events(r, id, v.FilterType)
	w.page(rw, r, id, "target", v)
}

// auditRows is the poller's target: 204 when the log has not moved, so the table is left alone.
func (w *webApp) auditRows(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	typ := r.URL.Query().Get("type")
	events, sig := w.events(r, id, typ)
	if sig == r.URL.Query().Get("known") {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	w.render(rw, "auditRows", &targetView{T: targetRow{ID: id}, Events: events, AuditSig: sig, FilterType: typ})
}

func (w *webApp) consentsTab(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, _, err := w.loadTarget(r, id)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "consents"
	v.Live, v.History, v.ConsentSig = w.consents(id, "")
	w.page(rw, r, id, "target", v)
}

// consentCards is the poller's target. An unchanged set returns 204, so a decision form
// someone is filling in is never re-rendered under them.
func (w *webApp) consentCards(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	live, history, sig := w.consents(id, "")
	if sig == r.URL.Query().Get("known") {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	w.render(rw, "consentCards", &targetView{T: targetRow{ID: id}, Live: live, History: history, ConsentSig: sig})
}

// resolveConsent approves (with the scopes actually ticked) or denies one ask. The grant is
// minted by the same registry path the TUI and the approvals CLI use.
func (w *webApp) resolveConsent(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad form", http.StatusBadRequest)
		return
	}
	askID := r.PathValue("id")
	targetID := r.FormValue("target")
	v, _, err := w.loadTarget(r, targetID)
	if err != nil {
		w.notFound(rw, r, err)
		return
	}
	v.Tab = "consents"

	popup := r.FormValue("popup") == "1"
	approve := r.FormValue("action") == "approve"
	var granted []string
	if approve {
		granted = r.Form["scope"]
		if len(granted) == 0 {
			if popup {
				live, sig := w.allLive("")
				w.render(rw, "consentPopup", &targetView{Live: live, ConsentSig: sig,
					Error: "Tick at least one capability to approve, or deny."})
				return
			}
			v.Live, v.History, v.ConsentSig = w.consents(targetID, "")
			v.Error = "Tick at least one scope to approve, or deny the request."
			w.page(rw, r, targetID, "target", v)
			return
		}
	}
	ttl, _ := strconv.Atoi(r.FormValue("ttl"))
	budget, _ := strconv.ParseFloat(r.FormValue("budget"), 64)

	ok, err := w.reg.ResolveConsent(w.e.operator, askID, granted, ttl, budget)
	if popup {
		live, sig := w.allLive(askID)
		pv := &targetView{Live: live, ConsentSig: sig}
		if err != nil {
			pv.Error = err.Error()
		} else if !ok {
			pv.Error = "That ask is no longer live — it expired or was already decided."
		}
		w.render(rw, "consentPopup", pv)
		return
	}
	v.Live, v.History, v.ConsentSig = w.consents(targetID, askID)
	switch {
	case err != nil:
		v.Error = err.Error()
	case !ok:
		v.Error = "That ask is no longer live — it expired, was already decided, or the agent gave up. It will re-ask on its next call."
	case approve:
		v.Notice = fmt.Sprintf("Approved %s for %d minutes.", strings.Join(granted, ", "), ttl)
	default:
		v.Notice = "Denied. No grant was minted."
	}
	w.page(rw, r, targetID, "target", v)
}
