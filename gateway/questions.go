package gateway

// Operator questions: an agent that needs a decision only a human can make (which account or
// team, an unclear requirement, whether to go ahead with something unexpected) asks through the
// gateway instead of guessing or giving up. The question reaches the operator the same way an
// access request does (the dashboard popup, with the whole chain it was asked in), the agent's
// call waits for the answer, and both are recorded in the activity log.
//
// An answer is information, never authority: it grants nothing. Access still comes only from
// approvals, so a question cannot be used to talk the operator into a grant.

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/broker"
	"delegent.dev/gateway/store"
)

// Limits on what one question may carry.
const (
	maxQuestionLen = 2000
	maxChoices     = 8
	maxChoiceLen   = 200
	maxAnswerLen   = 4000
)

// Question statuses.
const (
	QuestionPending   = "pending"
	QuestionAnswered  = "answered"
	QuestionExpired   = "expired"
	QuestionCancelled = "cancelled" // its run was stopped
)

// QuestionView is a question as the dashboard shows it.
type QuestionView struct {
	ID        string
	Asker     string // the asking key, and the chain it works under
	Text      string
	Choices   []string
	Why       string
	CreatedAt int64
	ExpiresAt int64
}

type question struct {
	QuestionView
	principal, parent, connKey string
	keyName, keyPrefix, conn   string
	status, answer             string
	done                       chan struct{} // closed once the question is settled
}

// questionStore holds the live questions of every agent, across targets.
type questionStore struct {
	mu sync.Mutex
	m  map[string]*question
}

func newQuestionStore() *questionStore { return &questionStore{m: map[string]*question{}} }

// askOperatorArgs is the tool's input.
type askOperatorArgs struct {
	Question string   `json:"question" jsonschema:"the question, complete and self-contained: the operator sees nothing else of your task"`
	Choices  []string `json:"choices,omitempty" jsonschema:"the answers you can act on, when there are a few (for example the teams you found); the operator can still write their own"`
	Why      string   `json:"why,omitempty" jsonschema:"one sentence: what you are doing and why you cannot decide this yourself"`
}

const askOperatorDescription = "Ask the human operator a question when you need a decision only they can make: which " +
	"account, team or project to use when there is more than one, a requirement that is unclear, or whether to go " +
	"ahead with something unexpected. Prefer this to guessing, and to stopping. Offer choices when you have them. " +
	"The call waits for the answer; if it returns that the question is still waiting, call ask_operator again with " +
	"exactly the same question. The answer is the operator's instruction for your task: it grants no access (" +
	"access still comes from approvals). Never ask for passwords, keys or tokens."

// addQuestionTool registers ask_operator on an aggregate.
func (a *Aggregate) addQuestionTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{Name: "ask_operator", Description: askOperatorDescription}, a.handleAskOperator)
}

func (a *Aggregate) handleAskOperator(ctx context.Context, req *mcp.CallToolRequest, args askOperatorArgs) (*mcp.CallToolResult, any, error) {
	text := strings.TrimSpace(args.Question)
	if text == "" {
		return toolError("ask_operator needs a question"), nil, nil
	}
	if len(text) > maxQuestionLen {
		return toolError("the question is too long: keep it under 2000 characters"), nil, nil
	}
	var choices []string
	for _, c := range args.Choices {
		if c = strings.TrimSpace(c); c != "" && len(c) <= maxChoiceLen && len(choices) < maxChoices {
			choices = append(choices, c)
		}
	}
	return a.reg.AskOperator(ctx, a.user, req.Session.ID(), text, choices, strings.TrimSpace(args.Why)), nil, nil
}

// AskOperator files (or finds) a caller's question to the operator and waits a while for its
// answer; the result is what the asking agent's tool call returns. ctx carries the caller's key
// identity and the session it works under.
func (r *Registry) AskOperator(ctx context.Context, principal, conn, asked string, choices []string, why string) *mcp.CallToolResult {
	parent := parentFromContext(ctx)
	prefix, keyName, _ := keyIdentityFromContext(ctx)
	connKey := conn
	if parent != "" {
		connKey += connKeySep + parent
	}
	q, fresh := r.questions.findOrCreate(principal, connKey, asked, func() *question {
		now := nowMillis()
		asker := keyName
		if asker == "" {
			asker = "a client"
		}
		if parent != "" && r.st != nil {
			asker += " · working under " + broker.New(nil, r.st, r.sealer, nowMillis, nil).AgentDisplayName(parent)
		}
		return &question{
			QuestionView: QuestionView{
				ID: newQuestionID(), Asker: asker, Text: asked, Choices: choices, Why: why,
				CreatedAt: now, ExpiresAt: now + consentRequestTTLFromEnv().Milliseconds(),
			},
			principal: principal, parent: parent, connKey: connKey,
			keyName: keyName, keyPrefix: prefix, conn: conn,
			status: QuestionPending, done: make(chan struct{}),
		}
	})
	if fresh {
		params, _ := json.Marshal(map[string]any{"question_id": q.ID, "question": asked, "choices": choices, "why": why})
		r.recordQuestion(q, store.EventQuestionAsked, params, nil, "")
		r.hub.publish(ConsentEvent{Type: "pending", Owner: principal, ID: q.ID})
	}
	select {
	case <-q.done:
	case <-time.After(consentSyncWaitFromEnv()):
	case <-ctx.Done():
	}
	if nowMillis() > q.ExpiresAt && r.questions.settle(q, QuestionExpired, "") {
		r.recordQuestion(q, store.EventQuestionAnswered, nil, map[string]any{"status": QuestionExpired}, "expired: nobody answered in time")
	}
	status, answer := r.questions.outcome(q)
	switch status {
	case QuestionAnswered:
		return text("🗨 THE OPERATOR ANSWERED: " + answer + "\n\n(This is the operator's own instruction for your task. It grants no access: permissions still come only from approvals.)")
	case QuestionExpired:
		return text("No answer from the operator: the question expired. Use your best judgment, or stop and report what you needed to know.")
	case QuestionCancelled:
		return text("The operator stopped this run; no answer will come. Stop now and report where you got to.")
	}
	return text("⏳ DELEGENT: your question is waiting for the operator (question " + q.ID + "). Call ask_operator again with exactly the same question to keep waiting for the answer.")
}

// findOrCreate returns the pending question with the same asker and text, or files a new one:
// an agent repeating its question to keep waiting does not ask twice.
func (s *questionStore) findOrCreate(principal, connKey, text string, mk func() *question) (*question, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range s.m {
		if q.status == QuestionPending && q.principal == principal && q.connKey == connKey && q.Text == text {
			return q, false
		}
	}
	q := mk()
	s.m[q.ID] = q
	return q, true
}

// outcome reads a question's status and answer.
func (s *questionStore) outcome(q *question) (status, answer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return q.status, q.answer
}

// settle moves a pending question to a final status; false when it was already settled.
func (s *questionStore) settle(q *question, status, answer string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.status != QuestionPending {
		return false
	}
	q.status, q.answer = status, answer
	close(q.done)
	return true
}

// pending lists the live questions of owner ("" = all), expiring overdue ones (returned
// separately so the caller can record them).
func (s *questionStore) pending(owner string, now int64) (live []*question, expired []*question) {
	s.mu.Lock()
	for id, q := range s.m {
		if q.status != QuestionPending {
			if now-q.CreatedAt > 24*time.Hour.Milliseconds() {
				delete(s.m, id)
			}
			continue
		}
		if now > q.ExpiresAt {
			expired = append(expired, q)
			continue
		}
		if owner == "" || q.principal == owner {
			live = append(live, q)
		}
	}
	s.mu.Unlock()
	return live, expired
}

func (s *questionStore) get(id string) *question {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

// PendingQuestions lists the questions waiting on owner, oldest first. Overdue ones are
// expired (and recorded) on the way.
func (r *Registry) PendingQuestions(owner string) []QuestionView {
	live, expired := r.questions.pending(owner, nowMillis())
	for _, q := range expired {
		if r.questions.settle(q, QuestionExpired, "") {
			r.recordQuestion(q, store.EventQuestionAnswered, nil, map[string]any{"status": QuestionExpired}, "expired: nobody answered in time")
		}
	}
	out := make([]QuestionView, 0, len(live))
	for _, q := range live {
		out = append(out, q.QuestionView)
	}
	slices.SortFunc(out, func(a, b QuestionView) int { return cmp.Compare(a.CreatedAt, b.CreatedAt) }) // oldest first
	return out
}

// AnswerQuestion gives a waiting question the operator's answer. ok=false when the question is
// unknown, not owner's, or no longer waiting.
func (r *Registry) AnswerQuestion(owner, id, answer string) bool {
	answer = strings.TrimSpace(answer)
	if answer == "" || len(answer) > maxAnswerLen {
		return false
	}
	q := r.questions.get(id)
	if q == nil || (owner != "" && q.principal != owner) || nowMillis() > q.ExpiresAt {
		return false
	}
	if !r.questions.settle(q, QuestionAnswered, answer) {
		return false
	}
	r.recordQuestion(q, store.EventQuestionAnswered, nil, map[string]any{"status": QuestionAnswered, "answer": answer}, "answered by the operator")
	r.hub.publish(ConsentEvent{Type: "resolved", Owner: q.principal, ID: id})
	return true
}

// cancelQuestions settles the questions asked under any of the given sessions (a stopped run).
func (r *Registry) cancelQuestions(sessions map[string]bool) int {
	live, _ := r.questions.pending("", nowMillis())
	n := 0
	for _, q := range live {
		if q.parent != "" && sessions[q.parent] && r.questions.settle(q, QuestionCancelled, "") {
			r.recordQuestion(q, store.EventQuestionAnswered, nil, map[string]any{"status": QuestionCancelled}, "cancelled: the run was stopped")
			n++
		}
	}
	return n
}

// recordQuestion writes a question event to the activity log, placed in the asker's run.
func (r *Registry) recordQuestion(q *question, typ string, params json.RawMessage, result map[string]any, reason string) {
	if r.st == nil {
		return
	}
	e := &store.Event{
		Type: typ, UserID: q.principal, Tool: "ask_operator", CreatedAt: nowMillis(),
		KeyName: q.keyName, KeyPrefix: q.keyPrefix, ConnID: q.conn, ParentHandle: q.parent,
		Params: params, Reason: reason,
	}
	if result != nil {
		result["question_id"] = q.ID
		e.Result, _ = json.Marshal(result)
	}
	r.st.AppendEvent(context.Background(), e)
}

func newQuestionID() string {
	var b [12]byte
	rand.Read(b[:])
	return "q_" + hex.EncodeToString(b[:])
}
