package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"delegent.dev/gateway/a2a"
)

// Upstream is what a Gateway fronts: something that publishes a tool list and executes
// tool calls with the credential the agent never sees. The MCP server is the first
// implementation; an A2A agent (its skills as tools) is the second. The gateway's
// authorization path is identical for both — only the wire differs.
type Upstream interface {
	// Tools lists the fronted tools (name, description, input schema — WITHOUT Delegent's
	// intent field, which the gateway injects).
	Tools(ctx context.Context) ([]*mcp.Tool, error)
	// Call executes one authorized tool call.
	Call(ctx context.Context, call UpstreamCall) (*mcp.CallToolResult, error)
	Close()
}

// headliner is optionally implemented by an Upstream that can name a tool's action more
// legibly than its description (an agent skill's name, for the consent prompt).
type headliner interface {
	Headline(tool string) string
}

// UpstreamCall is one authorized call on its way out: the tool, its (intent-stripped)
// arguments, and the caller's session handle — the lineage tag an agent upstream echoes
// back on its own calls (see a2a.SessionHeader).
type UpstreamCall struct {
	Name    string
	Args    map[string]any
	Session string
	// ContextID, when set, is the A2A conversation every call of this run to this agent
	// shares (see runContextID); it replaces any context_id the caller passed.
	ContextID string
}

// --- MCP ---

type mcpUpstream struct {
	sess *mcp.ClientSession
}

func (u *mcpUpstream) Tools(ctx context.Context) ([]*mcp.Tool, error) {
	res, err := u.sess.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

func (u *mcpUpstream) Call(ctx context.Context, c UpstreamCall) (*mcp.CallToolResult, error) {
	return u.sess.CallTool(ctx, &mcp.CallToolParams{Name: c.Name, Arguments: c.Args})
}

func (u *mcpUpstream) Close() { u.sess.Close() }

// --- A2A ---

// a2aUpstream fronts one agent: each card skill is a tool taking {message, context_id}; the
// built-in get_task resumes a task the agent handed back unfinished. Long tasks are polled,
// with state changes forwarded as MCP progress to the calling client.
type a2aUpstream struct {
	client *a2a.Client
	card   *a2a.Card
	skills map[string]a2a.Skill // tool name → skill

	// inflight remembers the task a (session, skill, message) started, so a client that
	// re-sends the same request — because its own tool-call timeout fired, or it is retrying
	// after a grant — is attached to the running task instead of starting a second one.
	mu       sync.Mutex
	inflight map[string]inflightTask
}

type inflightTask struct {
	taskID    string
	startedAt time.Time
}

// a2aWait bounds how long one tool call waits on a long-running agent task before handing the
// task back ("still working — check with get_task"). It must stay under the MCP clients' own
// tool-call timeouts (a minute is common), or a slow agent makes the client time out and retry.
// DELEGENT_A2A_WAIT overrides it (a Go duration).
const defaultA2AWait = 25 * time.Second

func a2aWaitFromEnv() time.Duration {
	if d, err := time.ParseDuration(os.Getenv("DELEGENT_A2A_WAIT")); err == nil && d > 0 {
		return d
	}
	return defaultA2AWait
}

// inflightTTL is how long a remembered task can be re-attached to; after that a repeat of the
// same message is a new request.
const inflightTTL = 30 * time.Minute

func newA2AUpstream(ctx context.Context, endpoint, credential string) (*a2aUpstream, error) {
	card, err := a2a.FetchCard(ctx, endpoint, credential)
	if err != nil {
		return nil, fmt.Errorf("fetch agent card: %w", err)
	}
	u := &a2aUpstream{
		client:   &a2a.Client{URL: card.URL, Credential: credential, PollTimeout: a2aWaitFromEnv()},
		card:     card,
		skills:   map[string]a2a.Skill{},
		inflight: map[string]inflightTask{},
	}
	for _, sk := range card.Skills {
		u.skills[a2a.ToolName(sk.ID)] = sk
	}
	return u, nil
}

// skillSchema is the input every skill tool takes: the message for the agent, and an
// optional context id to continue an earlier exchange.
func skillSchema(sk a2a.Skill) map[string]any {
	desc := "The request for the agent, in plain language."
	if len(sk.Examples) > 0 {
		desc += " Example: " + sk.Examples[0]
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"message":    map[string]any{"type": "string", "description": desc},
			"context_id": map[string]any{"type": "string", "description": "To follow up on an earlier reply from this agent (\"now email that to bob\", \"shorten it\"), pass the context_id that reply ended with; the agent then sees the earlier turns. Leave it out for a new request. Inside a Delegent run this is automatic: every request of the run to this agent is one conversation."},
		},
		"required": []string{"message"},
	}
}

var taskSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"task_id": map[string]any{"type": "string", "description": "The exact task id the agent returned (e.g. task-researcher-1)."},
		"message": map[string]any{"type": "string", "description": "ONLY when the task is waiting for input: your answer. Leave it out for a status check."},
	},
	"required": []string{"task_id"},
}

func (u *a2aUpstream) Tools(context.Context) ([]*mcp.Tool, error) {
	out := make([]*mcp.Tool, 0, len(u.card.Skills)+1)
	seen := map[string]bool{}
	for _, sk := range u.card.Skills {
		name := a2a.ToolName(sk.ID)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, &mcp.Tool{Name: name, Description: a2a.SkillDescription(sk), InputSchema: skillSchema(sk)})
	}
	if !seen[a2a.TaskTool] {
		out = append(out, &mcp.Tool{Name: a2a.TaskTool, Description: a2a.TaskToolDescription, InputSchema: taskSchema})
	}
	return out, nil
}

func (u *a2aUpstream) Call(ctx context.Context, c UpstreamCall) (*mcp.CallToolResult, error) {
	str := func(k string) string {
		s, _ := c.Args[k].(string)
		return strings.TrimSpace(s)
	}
	progress := func(line string) { emitProgress(ctx, u.card.Name+": "+line) }
	var res *a2a.Result
	var err error
	if c.Name == a2a.TaskTool {
		taskID := str("task_id")
		if taskID == "" {
			return toolError("get_task needs a task_id"), nil
		}
		// A message is only an answer when the task is actually waiting for one. Any other
		// get_task is a status check — a model that pads it with "please check my task" must
		// not restart the work.
		cur, gerr := u.client.GetTask(ctx, taskID, c.Session)
		switch {
		case gerr != nil:
			res, err = nil, gerr
		case str("message") != "" && a2a.NeedsCaller(cur.State):
			res, err = u.client.Send(ctx, str("message"), a2a.SendOpts{TaskID: taskID, Session: c.Session, Progress: progress})
		case a2a.Terminal(cur.State) || a2a.NeedsCaller(cur.State):
			res = cur
		default:
			res, err = u.client.Wait(ctx, taskID, c.Session, progress)
		}
	} else {
		sk, ok := u.skills[c.Name]
		if !ok {
			return toolError("unknown skill " + c.Name), nil
		}
		msg := str("message")
		if msg == "" {
			return toolError("'" + c.Name + "' needs a message"), nil
		}
		contextID := str("context_id")
		if c.ContextID != "" {
			contextID = c.ContextID
		}
		key := c.Session + "|" + sk.ID + "|" + contextID + "|" + msg
		if taskID := u.running(key); taskID != "" {
			// The same request is already being worked: attach to it rather than start twice.
			progress("re-attached to the running task " + taskID)
			res, err = u.client.Wait(ctx, taskID, c.Session, progress)
		} else {
			// Start the task without waiting, and remember it before polling, so a stopped run
			// can cancel it from its first moment (see cancelSessions).
			res, err = u.client.Send(ctx, msg, a2a.SendOpts{Skill: sk.ID, ContextID: contextID, Session: c.Session, NoWait: true})
			if err == nil && res != nil && res.TaskID != "" && !a2a.Terminal(res.State) && !a2a.NeedsCaller(res.State) {
				u.remember(key, res)
				res, err = u.client.Wait(ctx, res.TaskID, c.Session, progress)
			}
		}
		if res != nil && res.TaskID != "" {
			u.remember(key, res)
		}
	}
	if err != nil {
		if res == nil {
			return nil, err
		}
		// A poll that broke mid-task still has the last task view: hand it back with the error.
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: renderA2A(res) + "\n(error: " + err.Error() + ")"}}}, nil
	}
	out := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: renderA2A(res)}}}
	if res.State == a2a.StateFailed || res.State == a2a.StateRejected {
		out.IsError = true
	}
	out.StructuredContent = map[string]any{"text": res.Text, "state": res.State, "task_id": res.TaskID, "context_id": res.ContextID}
	if wantsRawA2A(ctx) {
		if m := rawA2A(res); m != nil {
			out.Meta = mcp.Meta{rawA2AMeta: m}
		}
	}
	return out, nil
}

// renderA2A is the model-facing text for an agent result: what the agent said, plus how to
// continue when it is not done.
func renderA2A(r *a2a.Result) string {
	var b strings.Builder
	b.WriteString(r.Text)
	switch r.State {
	case "":
		// an immediate message reply — nothing to add
	case a2a.StateCompleted:
	case a2a.StateInputRequired:
		b.WriteString("\n\n[agent needs input — answer with get_task {task_id: \"" + r.TaskID + "\", message: …}]")
	case a2a.StateAuthRequired:
		b.WriteString("\n\n[agent is waiting for an authorization it cannot get on its own (task " + r.TaskID + ")]")
	case a2a.StateFailed, a2a.StateRejected, a2a.StateCanceled:
		b.WriteString("\n\n[agent task " + r.TaskID + " " + r.State + "]")
	default:
		b.WriteString("\n\n[agent task " + r.TaskID + " is still " + r.State + " — check later with get_task {task_id: \"" + r.TaskID + "\"}]")
	}
	if r.ContextID != "" {
		b.WriteString("\n(context_id: " + r.ContextID + ")")
	}
	return strings.TrimSpace(b.String())
}

// running returns the task id an identical request started, if it is still fresh.
func (u *a2aUpstream) running(key string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	t, ok := u.inflight[key]
	if !ok {
		return ""
	}
	if time.Since(t.startedAt) > inflightTTL {
		delete(u.inflight, key)
		return ""
	}
	return t.taskID
}

// remember records (or forgets, once terminal) the task behind a request.
func (u *a2aUpstream) remember(key string, res *a2a.Result) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if a2a.Terminal(res.State) {
		delete(u.inflight, key)
		return
	}
	if _, ok := u.inflight[key]; !ok {
		u.inflight[key] = inflightTask{taskID: res.TaskID, startedAt: time.Now()}
	}
}

// CancelAgentTask cancels one task on the agent this target fronts. Only an A2A target has
// tasks; for any other target it is an error.
func (g *Gateway) CancelAgentTask(ctx context.Context, taskID, session string) error {
	u, ok := g.upstream.(*a2aUpstream)
	if !ok {
		return errors.New("not an agent target")
	}
	res, err := u.client.CancelTask(ctx, taskID, session)
	if err != nil {
		return err
	}
	if res != nil && res.State != a2a.StateCanceled {
		return fmt.Errorf("task %s is %s, not canceled", taskID, res.State)
	}
	return nil
}

// AgentTask is a task an agent target is working on, as the gateway started it.
type AgentTask struct {
	TaskID, Session, Skill, Message string
	StartedAt                       int64 // unix ms
}

// RunningAgentTasks lists the tasks this agent target started for any of the given sessions
// and has not yet seen finish: a task is known here from its first moment, before any reply
// (and so before the activity log) carries its id.
func (g *Gateway) RunningAgentTasks(sessions map[string]bool) []AgentTask {
	u, ok := g.upstream.(*a2aUpstream)
	if !ok {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []AgentTask
	for key, t := range u.inflight {
		parts := strings.SplitN(key, "|", 4)
		if len(parts) != 4 || !sessions[parts[0]] || time.Since(t.startedAt) > inflightTTL {
			continue
		}
		out = append(out, AgentTask{TaskID: t.taskID, Session: parts[0], Skill: parts[1], Message: parts[3], StartedAt: t.startedAt.UnixMilli()})
	}
	return out
}

// AgentTaskStatus asks the agent this target fronts where one of its tasks stands: its state
// and its latest word (the status note of a running task, or the result of a finished one).
func (g *Gateway) AgentTaskStatus(ctx context.Context, taskID, session string) (state, text string, err error) {
	u, ok := g.upstream.(*a2aUpstream)
	if !ok {
		return "", "", errors.New("not an agent target")
	}
	res, err := u.client.GetTask(ctx, taskID, session)
	if err != nil {
		return "", "", err
	}
	return res.State, res.Text, nil
}

// cancelSessions cancels, on the agent, every task this upstream started for a call made under
// one of the given sessions (a stopped run), and forgets them. Best effort: an agent that does
// not answer is left to finish on its own. Returns how many tasks were cancelled.
func (u *a2aUpstream) cancelSessions(ctx context.Context, sessions map[string]bool) int {
	type job struct{ key, taskID, session string }
	var jobs []job
	u.mu.Lock()
	for key, t := range u.inflight {
		session, _, _ := strings.Cut(key, "|")
		if sessions[session] {
			jobs = append(jobs, job{key, t.taskID, session})
			delete(u.inflight, key)
		}
	}
	u.mu.Unlock()
	canceled := 0
	for _, j := range jobs {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if _, err := u.client.CancelTask(cctx, j.taskID, j.session); err == nil {
			canceled++
		} else {
			log.Printf("[delegent] stop run: cancelling task %s on %s failed: %v", j.taskID, u.card.Name, err)
		}
		cancel()
	}
	return canceled
}

// skillTool maps a skill id from message metadata to its tool name; with no id, the agent's
// sole skill; "" when the agent has several and none was named.
func (u *a2aUpstream) skillTool(skillID string) string {
	if skillID != "" {
		if _, ok := u.skills[a2a.ToolName(skillID)]; ok {
			return a2a.ToolName(skillID)
		}
		return ""
	}
	if len(u.card.Skills) == 1 {
		return a2a.ToolName(u.card.Skills[0].ID)
	}
	return ""
}

func (u *a2aUpstream) skillIDs() []string {
	var out []string
	for _, sk := range u.card.Skills {
		out = append(out, sk.ID)
	}
	return out
}

// Headline is the short action the consent prompt shows for a skill ("research a topic"),
// instead of the full description-plus-examples the tool list carries.
func (u *a2aUpstream) Headline(tool string) string {
	if tool == a2a.TaskTool {
		return "check on a task it started"
	}
	if sk, ok := u.skills[tool]; ok && sk.Name != "" {
		return strings.ToLower(sk.Name[:1]) + sk.Name[1:]
	}
	return ""
}

// Detail is the message a skill call will send, trimmed for the consent prompt.
func (u *a2aUpstream) Detail(tool string, args map[string]any) string {
	msg, _ := args["message"].(string)
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return ""
	}
	const max = 240
	if len(msg) > max {
		msg = msg[:max] + "…"
	}
	return msg
}

func (u *a2aUpstream) Close() {}
