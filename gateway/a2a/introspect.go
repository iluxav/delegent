package a2a

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"delegent.dev/gateway/introspect"
)

// TaskTool is the built-in tool every A2A target exposes besides its skills: resume/inspect a
// task the agent handed back unfinished (input-required, or still working past the poll
// window). It classifies as a read.
const TaskTool = "get_task"

// TaskToolDescription is get_task's human-facing description.
const TaskToolDescription = "Check on a task this agent started earlier: pass the exact task_id it returned. It never starts new work. Pass a message ONLY when the task said it needs input; otherwise leave it out."

var toolNameSafe = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// ToolName turns a skill id into a name inside the tool-name charset MCP clients enforce.
func ToolName(skillID string) string {
	n := toolNameSafe.ReplaceAllString(strings.TrimSpace(skillID), "_")
	n = strings.Trim(n, "_")
	if n == "" {
		n = "skill"
	}
	return n
}

// Introspect fetches the agent's card and drafts one classification per skill, plus the
// built-in get_task tool. Same contract as introspect.Introspect for MCP servers: the draft is
// a suggestion the operator signs.
func Introspect(ctx context.Context, endpoint, credential string) (*introspect.Result, *Card, error) {
	card, err := FetchCard(ctx, endpoint, credential)
	if err != nil {
		return nil, nil, err
	}
	return DraftCard(card), card, nil
}

// DraftCard drafts classifications for a card already in hand.
func DraftCard(card *Card) *introspect.Result {
	out := &introspect.Result{Tools: make([]introspect.DraftTool, 0, len(card.Skills)+1)}
	seen := map[string]bool{}
	for _, sk := range card.Skills {
		name := ToolName(sk.ID)
		if seen[name] {
			continue
		}
		seen[name] = true
		d := introspect.DraftSkill(name, sk.Name, sk.Description, sk.Tags)
		d.Description = SkillDescription(sk)
		out.Tools = append(out.Tools, d)
	}
	if !seen[TaskTool] {
		out.Tools = append(out.Tools, introspect.DraftSkill(TaskTool, "get task", TaskToolDescription, []string{"read"}))
	}
	return out
}

// SkillDescription is the tool description a skill is published under: its display name, its
// description, and its examples, so the calling model knows what message to send.
func SkillDescription(sk Skill) string {
	var b strings.Builder
	if sk.Name != "" && sk.Name != sk.ID {
		b.WriteString(sk.Name)
		if sk.Description != "" {
			b.WriteString(": ")
		}
	}
	b.WriteString(sk.Description)
	if len(sk.Examples) > 0 {
		b.WriteString(" Examples: ")
		for i, e := range sk.Examples {
			if i > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(fmt.Sprintf("%q", e))
		}
	}
	return strings.TrimSpace(b.String())
}
