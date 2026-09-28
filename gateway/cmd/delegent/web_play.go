package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/store"
)

// playRun is one playground run as the dashboard tracks it while the agent works: what was
// sent, and — once the send returns — the agent's answer or the reason it did not answer. The
// run's events themselves land in the activity log like any other call; the Runs page finds
// them by the run's connection id (gateway.PlaygroundConn).
type playRun struct {
	Nonce, Target, TargetName, Skill, Message string
	StartedAt                                 time.Time
	Done                                      bool
	Answer, Err                               string
}

// playView is the playground page: an agent, its skills, and a message to send.
type playView struct {
	T        targetRow
	Skills   []gateway.PlaygroundSkill
	Skill    string // selected skill id
	Message  string
	Intent   string
	Error    string
	Run      *playRun // the waiting page: the run just started
	RunURL   string   // the waiting page's own url (polled)
	Elapsed  string
	Slow     bool // waiting longer than expected
	NoSkills bool
	// Unclassified names skills whose tool has no effect yet: the guarded path refuses them
	// (fail closed) until the Tool policy tab classifies them.
	Unclassified []string
}

func (w *webApp) play(nonce string) *playRun {
	w.playMu.Lock()
	defer w.playMu.Unlock()
	return w.plays[nonce]
}

func (w *webApp) loadPlay(r *http.Request, id string) (*playView, *store.Target, error) {
	t, err := w.e.st.GetTarget(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	a := &adminEnv{e: w.e, reg: w.reg}
	v := &playView{T: a.targetRowFor(r, t)}
	if t.Kind != gateway.TargetKindA2A {
		return v, t, fmt.Errorf("%s is an MCP server; the playground runs agents", t.Name)
	}
	if !t.Enabled {
		return v, t, fmt.Errorf("%s is disabled — enable it first", t.Name)
	}
	skills, err := w.reg.PlaygroundSkills(r.Context(), id)
	if err != nil {
		return v, t, fmt.Errorf("%s is not reachable right now: %v", t.Name, err)
	}
	v.Skills = skills
	v.NoSkills = len(skills) == 0
	if ad, err := w.e.st.GetAdapter(r.Context(), t.AdapterID); err == nil {
		if tools, err := provision.ParseAdapterTools(ad.Doc); err == nil {
			for _, tool := range tools {
				if provision.IsUnknown(tool.Effect) {
					v.Unclassified = append(v.Unclassified, tool.Name)
				}
			}
		}
	}
	if len(skills) > 0 {
		v.Skill = skills[0].ID
		if len(skills[0].Examples) > 0 {
			v.Message = skills[0].Examples[0]
		}
	}
	return v, t, nil
}

// playPage shows the playground for an agent: pick a skill, write the message, run.
func (w *webApp) playPage(rw http.ResponseWriter, r *http.Request) {
	v, _, err := w.loadPlay(r, r.PathValue("id"))
	if err != nil {
		if v == nil {
			w.notFound(rw, r, err)
			return
		}
		v.Error = err.Error()
	}
	w.page(rw, r, v.T.ID, "playPage", v)
}

// playStart sends the message as the operator's playground client, in the background, and
// sends the person to the waiting page, which turns into the live run as soon as its first
// event lands.
func (w *webApp) playStart(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, t, err := w.loadPlay(r, id)
	if err != nil {
		if v == nil {
			w.notFound(rw, r, err)
			return
		}
		v.Error = err.Error()
		w.page(rw, r, id, "playPage", v)
		return
	}
	skill, message, intent := strings.TrimSpace(r.FormValue("skill")), strings.TrimSpace(r.FormValue("message")), strings.TrimSpace(r.FormValue("intent"))
	v.Skill, v.Message, v.Intent = skill, message, intent
	known := false
	for _, sk := range v.Skills {
		if sk.ID == skill {
			known = true
		}
	}
	switch {
	case !known:
		v.Error = "pick one of the agent's skills"
	case message == "":
		v.Error = "write the message the agent should work on"
	}
	if v.Error != "" {
		w.page(rw, r, id, "playPage", v)
		return
	}
	if intent == "" {
		intent = "playground run from the dashboard"
	}
	nonce := newNonce()
	run := &playRun{Nonce: nonce, Target: t.ID, TargetName: t.Name, Skill: skill, Message: message, StartedAt: time.Now()}
	w.playMu.Lock()
	if w.plays == nil {
		w.plays = map[string]*playRun{}
	}
	w.plays[nonce] = run
	w.playMu.Unlock()
	user := w.e.operator
	go func() {
		// Not the request's context: the person is being redirected while the agent works.
		answer, err := w.reg.PlaygroundSend(context.Background(), user, t.ID, nonce, skill, message, intent)
		w.playMu.Lock()
		run.Done, run.Answer = true, answer
		if err != nil {
			run.Err = err.Error()
		}
		w.playMu.Unlock()
		if err != nil {
			log.Printf("[delegent] playground %s on %s: %v", nonce, t.ID, err)
		}
	}()
	w.redirect(rw, r, "/play/"+t.ID+"/"+nonce)
}

// playWait is the page between Run and the live run: it polls itself until the run's first
// event is in the log, then sends the person to the run. A send that failed before any event
// was logged (the agent unreachable, the call refused) is reported here instead.
func (w *webApp) playWait(rw http.ResponseWriter, r *http.Request) {
	id, nonce := r.PathValue("id"), r.PathValue("nonce")
	if x := w.findRunByConn(r, gateway.PlaygroundConn(nonce)); x != nil {
		w.redirect(rw, r, "/runs/"+x.Root)
		return
	}
	run := w.play(nonce)
	if run == nil {
		w.page(rw, r, id, "runMissing", map[string]any{"Root": "playground " + nonce})
		return
	}
	v := &playView{Run: run, RunURL: "/play/" + id + "/" + nonce}
	if t, err := w.e.st.GetTarget(r.Context(), id); err == nil {
		v.T = (&adminEnv{e: w.e, reg: w.reg}).targetRowFor(r, t)
	}
	el := time.Since(run.StartedAt).Round(time.Second)
	v.Elapsed, v.Slow = el.String(), el > 20*time.Second
	rw.Header().Set("Cache-Control", "no-store")
	w.page(rw, r, id, "playWait", v)
}

// redirect sends the browser elsewhere: a full navigation for htmx (the target is a whole
// page with its own polling), a plain 303 otherwise.
func (w *webApp) redirect(rw http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") != "" {
		rw.Header().Set("HX-Redirect", to)
		rw.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(rw, r, to, http.StatusSeeOther)
}

var nonceMu sync.Mutex

func newNonce() string {
	nonceMu.Lock()
	defer nonceMu.Unlock()
	return strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano())[6:])
}
