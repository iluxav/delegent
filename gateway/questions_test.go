package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/store"
)

func questionRegistry(t *testing.T) (*Registry, *store.MemStore, context.Context) {
	t.Helper()
	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "50ms")
	st := store.NewMemStore()
	st.PutSession(context.Background(), &store.Session{Handle: "sess_pm", Principal: "usr_op"})
	r := NewRegistry(st, keyring.Sealer(nil))
	ctx := ctxWithToken(t, &auth.TokenInfo{UserID: "usr_op", Expiration: time.Now().Add(time.Hour), Extra: map[string]any{
		"key_prefix": "dgk_dev", "key_name": "devops prod", "parent_session": "sess_pm",
	}})
	return r, st, ctx
}

// An agent's question waits for the operator: while unanswered the call says so (and asking
// again does not file a second question); once answered, the answer comes back, marked as the
// operator's instruction that grants nothing. Both ends are in the activity log, in the run.
func TestAskOperatorWaitsForTheAnswer(t *testing.T) {
	r, st, ctx := questionRegistry(t)
	res := resultText(r.AskOperator(ctx, "usr_op", "conn1", "Which Vercel team?", []string{"iluxav", "acme"}, "two teams found"))
	if !strings.Contains(res, "waiting for the operator") {
		t.Fatalf("first call = %q", res)
	}
	r.AskOperator(ctx, "usr_op", "conn1", "Which Vercel team?", nil, "")
	qs := r.PendingQuestions("usr_op")
	if len(qs) != 1 {
		t.Fatalf("asking again filed another question: %d pending", len(qs))
	}
	q := qs[0]
	if q.Text != "Which Vercel team?" || len(q.Choices) != 2 || !strings.HasPrefix(q.Asker, "devops prod · working under") {
		t.Errorf("question = %+v", q)
	}
	if r.PendingQuestions("usr_someone_else") != nil && len(r.PendingQuestions("usr_someone_else")) != 0 {
		t.Error("another operator sees this question")
	}
	if r.AnswerQuestion("usr_someone_else", q.ID, "acme") {
		t.Fatal("another operator answered it")
	}

	t.Setenv("DELEGENT_CONSENT_SYNC_WAIT", "5s")
	done := make(chan string, 1)
	go func() {
		done <- resultText(r.AskOperator(ctx, "usr_op", "conn1", "Which Vercel team?", nil, ""))
	}()
	time.Sleep(20 * time.Millisecond)
	if !r.AnswerQuestion("usr_op", q.ID, "iluxav") {
		t.Fatal("the answer was not accepted")
	}
	select {
	case got := <-done:
		if !strings.Contains(got, "THE OPERATOR ANSWERED: iluxav") || !strings.Contains(got, "grants no access") {
			t.Errorf("answer = %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiting call did not get the answer")
	}
	if r.AnswerQuestion("usr_op", q.ID, "again") {
		t.Error("a question was answered twice")
	}
	if len(r.PendingQuestions("usr_op")) != 0 {
		t.Error("an answered question is still pending")
	}

	evs, _ := st.ListEvents(context.Background(), store.EventFilter{UserID: "usr_op", Limit: store.EventLimitAll})
	var asked, answered *store.Event
	for _, e := range evs {
		switch e.Type {
		case store.EventQuestionAsked:
			asked = e
		case store.EventQuestionAnswered:
			answered = e
		}
	}
	if asked == nil || answered == nil {
		t.Fatalf("events = %+v", evs)
	}
	if asked.ParentHandle != "sess_pm" || asked.KeyName != "devops prod" || !strings.Contains(string(asked.Params), "Which Vercel team?") {
		t.Errorf("asked event = %+v", asked)
	}
	var out map[string]any
	json.Unmarshal(answered.Result, &out)
	if out["answer"] != "iluxav" || out["status"] != QuestionAnswered || out["question_id"] != q.ID {
		t.Errorf("answered event result = %v", out)
	}
}

// A question nobody answers expires; a question in a stopped run is cancelled.
func TestQuestionsExpireAndAreCancelledWithTheirRun(t *testing.T) {
	r, _, ctx := questionRegistry(t)
	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "1ms")
	r.AskOperator(ctx, "usr_op", "conn1", "Anyone there?", nil, "")
	time.Sleep(5 * time.Millisecond)
	if got := resultText(r.AskOperator(ctx, "usr_op", "conn2", "Anyone there?", nil, "")); !strings.Contains(got, "waiting") && !strings.Contains(got, "expired") {
		t.Errorf("second asker = %q", got)
	}
	if len(r.PendingQuestions("usr_op")) != 0 {
		t.Error("expired questions are still offered to the operator")
	}

	t.Setenv("DELEGENT_CONSENT_REQUEST_TTL", "30m")
	r.AskOperator(ctx, "usr_op", "conn3", "Deploy now?", nil, "")
	if n := len(r.PendingQuestions("usr_op")); n != 1 {
		t.Fatalf("pending = %d", n)
	}
	rep, err := r.StopRun("usr_op", "sess_pm")
	if err != nil || rep.Questions != 1 {
		t.Fatalf("stop: %+v %v", rep, err)
	}
}
