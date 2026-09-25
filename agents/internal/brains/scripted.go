// Package brains holds the two ways a demo agent decides what to do: a deterministic script
// per role (the default — every run behaves the same, so the consent chain is easy to read)
// and an LLM on a local Ollama that picks Delegent tools itself.
package brains

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"delegent.dev/agents/internal/a2aserver"
	"delegent.dev/agents/internal/dclient"
	"delegent.dev/gateway/a2a"
)

// Deps is what a brain may use: Delegent (nil for leaf agents that call nothing), and a pace:
// how long each unit of "work" takes, so a run is slow enough to watch on the dashboard.
type Deps struct {
	Delegent *dclient.Client
	Logf     func(format string, args ...any)
	Pace     time.Duration
}

// work spends one paced step on a described activity, reporting it as the task's status so
// the caller (and Delegent's progress) can see what the agent is doing.
func (d Deps) work(ctx context.Context, c a2aserver.Call, what string) {
	c.Status(what)
	d.Logf("%s", what)
	if d.Pace <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d.Pace):
	}
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	mailRe  = regexp.MustCompile(`(?i)\b(e-?mail|send (it |the (summary|report|result) )?to|notify)\b`)
	// noMailRe catches "do not email", "don't send it", "no email", "without emailing", …
	noMailRe = regexp.MustCompile(`(?i)\b(do not|don'?t|never|no|without|not)\s+(e-?mail\w*|send\w*|notify\w*)\b`)
)

// wantsEmail decides whether a request asks for its result to be emailed: it must mention
// emailing, name an address, and not say the opposite. Returns the address.
func wantsEmail(text string) (string, bool) {
	if noMailRe.MatchString(text) || !mailRe.MatchString(text) {
		return "", false
	}
	to := emailRe.FindString(text)
	return to, to != ""
}

// Librarian: a leaf. Answers search_docs from a tiny canned corpus.
func Librarian(d Deps) a2aserver.Handler {
	corpus := map[string][]string{
		"solar":    {"Solar panel efficiency reached 24% in mass-market modules in 2025.", "Payback period for residential installs averages 7-9 years in sunny regions."},
		"delegent": {"Delegent is a consent gateway: every agent call is checked, approved by a human when required, and receipted.", "Agents behind Delegent never hold vendor secrets."},
		"coffee":   {"Arabica accounts for about 60% of world coffee production.", "Cold brew extracts fewer acids, giving a smoother taste."},
	}
	return func(ctx context.Context, c a2aserver.Call) (string, error) {
		d.work(ctx, c, "opening the archive")
		d.work(ctx, c, "searching the index for: "+firstLine(c.Text))
		q := strings.ToLower(c.Text)
		var hits []string
		for k, lines := range corpus {
			if strings.Contains(q, k) {
				hits = append(hits, lines...)
			}
		}
		if len(hits) == 0 {
			hits = []string{"No indexed document matches; the archive holds notes on solar, delegent, and coffee."}
		}
		return "Found " + fmt.Sprint(len(hits)) + " note(s):\n- " + strings.Join(hits, "\n- "), nil
	}
}

// Mailer: a leaf. "Sends" email by logging it.
func Mailer(d Deps) a2aserver.Handler {
	return func(ctx context.Context, c a2aserver.Call) (string, error) {
		to := "the operator"
		if m := emailRe.FindString(c.Text); m != "" {
			to = m
		}
		d.work(ctx, c, "composing the message")
		d.work(ctx, c, "delivering to "+to)
		d.Logf("📧 EMAIL SENT to %s:\n%s", to, indent(c.Text))
		return "Email sent to " + to + " (" + fmt.Sprint(len(c.Text)) + " chars).", nil
	}
}

// Researcher: asks the librarian through Delegent, writes a summary, and — only when the
// request asks for it — emails it through the mailer, again through Delegent, under the
// session it was called with.
func Researcher(d Deps) a2aserver.Handler {
	return func(ctx context.Context, c a2aserver.Call) (string, error) {
		s, err := d.Delegent.Open(ctx, c.Session)
		if err != nil {
			return "", err
		}
		defer s.Close()
		d.work(ctx, c, "reading the request")
		// A follow-up in an existing conversation that only asks to send: email the last
		// result instead of researching again.
		if prev := lastReply(c.History); prev != "" && mailRe.MatchString(c.Text) && !noMailRe.MatchString(c.Text) && len(c.Text) < 160 {
			to := emailRe.FindString(c.Text)
			if to == "" {
				return "Tell me the address to send it to.", nil
			}
			d.work(ctx, c, "emailing the previous summary to "+to)
			sent, err := s.Call(ctx, "mailer__send_email", map[string]any{"message": "To: " + to + "\nSubject: " + firstLine(prev) + "\n\n" + prev}, "The follow-up asked for the previous summary to be emailed to "+to, c.Status)
			if err != nil {
				return "", err
			}
			return sent, nil
		}
		if topic(c.Text) == "" {
			// "email it to x" with no conversation behind it: nothing to send, nothing to research
			return "There is nothing to send: this conversation has no earlier result. Pass the context_id of the research you mean, or tell me what to research.", nil
		}
		var notes string
		if searchTool := s.Find(ctx, "search_web"); searchTool != "" {
			// A real web target is registered: search it, read the top hit, and keep the
			// librarian for the company's own notes.
			d.work(ctx, c, "searching the web")
			found, err := s.Call(ctx, searchTool, map[string]any{"query": topic(c.Text), "max_results": 5}, "Researcher looks for public sources on: "+firstLine(c.Text), c.Status)
			if err != nil {
				return "", err
			}
			notes = "Web results:\n" + found
			if u, fetchTool := firstURL(found), s.Find(ctx, "fetch_page"); u != "" && fetchTool != "" {
				d.work(ctx, c, "reading "+u)
				page, err := s.Call(ctx, fetchTool, map[string]any{"url": u, "max_chars": 2500}, "Researcher reads the top result for: "+firstLine(c.Text), c.Status)
				if err == nil {
					notes += "\n\nFrom " + u + ":\n" + page
				} else {
					notes += "\n\n(could not read " + u + ": " + err.Error() + ")"
				}
			}
			// The archive advertises what it holds ("Topics covered: …"); ask it only then.
			if covers(s.Describe(ctx, "librarian__search_docs"), c.Text) {
				d.work(ctx, c, "checking the company archive")
				if archive, err := s.Call(ctx, "librarian__search_docs", map[string]any{"message": c.Text}, "Researcher checks the company archive for: "+firstLine(c.Text), c.Status); err == nil {
					notes += "\n\nCompany archive:\n" + archive
				}
			} else {
				d.Logf("skipping the librarian: its archive does not cover %q", topic(c.Text))
			}
		} else {
			d.work(ctx, c, "asking the librarian")
			archive, err := s.Call(ctx, "librarian__search_docs", map[string]any{"message": c.Text}, "Researcher needs source material for: "+firstLine(c.Text), c.Status)
			if err != nil {
				return "", err
			}
			notes = archive
		}
		d.work(ctx, c, "writing the summary")
		summary := "Research summary for \"" + firstLine(c.Text) + "\":\n" + notes
		if to, ok := wantsEmail(c.Text); ok {
			c.Status("emailing the summary to " + to)
			sent, err := s.Call(ctx, "mailer__send_email", map[string]any{"message": "To: " + to + "\nSubject: " + firstLine(c.Text) + "\n\n" + summary}, "The request asked for the summary to be emailed to "+to, c.Status)
			if err != nil {
				return summary + "\n\n(email NOT sent: " + err.Error() + ")", nil
			}
			summary += "\n\n" + sent
		}
		return summary, nil
	}
}

// Assistant: a second-level orchestrator, so the chain is human → assistant → researcher →
// librarian/mailer. It delegates the whole job to the researcher.
func Assistant(d Deps) a2aserver.Handler {
	return func(ctx context.Context, c a2aserver.Call) (string, error) {
		s, err := d.Delegent.Open(ctx, c.Session)
		if err != nil {
			return "", err
		}
		defer s.Close()
		d.work(ctx, c, "planning the report")
		d.work(ctx, c, "handing the research to the researcher")
		out, err := s.Call(ctx, "researcher__research_topic", map[string]any{"message": c.Text}, "The assistant delegates the research for: "+firstLine(c.Text), c.Status)
		if err != nil {
			return "", err
		}
		d.work(ctx, c, "formatting the report")
		return "Report prepared by the assistant.\n\n" + out, nil
	}
}

// topic strips the request down to a search query: the first sentence, minus delivery
// instructions such as "and email it to …".
func topic(s string) string {
	t := firstLine(s)
	if i := mailRe.FindStringIndex(t); i != nil {
		t = strings.TrimSpace(t[:i[0]])
	}
	t = strings.TrimRight(t, " ,;:and")
	for _, p := range []string{"research ", "look up ", "find out about ", "tell me about "} {
		if strings.HasPrefix(strings.ToLower(t), p) {
			t = t[len(p):]
		}
	}
	return strings.TrimSpace(t)
}

var urlRe = regexp.MustCompile(`https?://[^\s)]+`)

func firstURL(s string) string { return urlRe.FindString(s) }

var coveredRe = regexp.MustCompile(`(?i)topics covered:\s*([^.]+)`)

// covers reads a tool's advertised "Topics covered: a, b, c" and reports whether the request
// mentions one of them. A description with no such line is taken to cover everything.
func covers(description, request string) bool {
	m := coveredRe.FindStringSubmatch(description)
	if m == nil {
		return true
	}
	req := strings.ToLower(request)
	for _, t := range strings.Split(m[1], ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		// match on the topic's first word too ("solar panels" ↔ "solar")
		if strings.Contains(req, t) || strings.Contains(req, strings.Fields(t)[0]) {
			return true
		}
	}
	return false
}

// lastReply is the agent's most recent answer in the conversation, or "".
func lastReply(h []a2a.Message) string {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Role == "agent" {
			return a2a.PartsText(h[i].Parts)
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i > 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

func indent(s string) string { return "    " + strings.ReplaceAll(s, "\n", "\n    ") }
