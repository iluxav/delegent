// demo-agent runs the demo A2A agents Delegent fronts in the agents-as-targets walkthrough
// (see agents/README.md). Four roles, each an A2A agent with one skill:
//
//	librarian   search_docs      leaf: answers from a canned corpus
//	mailer      send_email       leaf: "sends" email by logging it
//	researcher  research_topic   calls librarian (and, on request, mailer) THROUGH Delegent
//	assistant   write_report     calls researcher through Delegent (a second hop)
//
// Every agent requires its own inbound secret — the one only Delegent holds — and the callers
// echo the X-Delegent-Session they were called under on their own outbound calls. Run one role
// with --role, or all four in one process with --all.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"delegent.dev/agents/internal/a2aserver"
	"delegent.dev/agents/internal/brains"
	"delegent.dev/agents/internal/dclient"
	"delegent.dev/gateway/a2a"
)

type role struct {
	name    string
	port    int
	skill   a2a.Skill
	caller  bool     // consumes other targets through Delegent
	tools   []string // Delegent tool prefixes the LLM brain may see (scripted brains ignore this)
	system  string
	handler func(brains.Deps) a2aserver.Handler
}

var roles = []role{
	{
		name: "librarian", port: 7101,
		skill:   a2a.Skill{ID: "search_docs", Name: "Search the document archive", Description: "Finds notes in the company archive and returns the matching passages. Topics covered: solar panels, Delegent, coffee. Nothing else is indexed, so do not ask about other topics.", Tags: []string{"read", "documents"}, Examples: []string{"find our notes on solar panels"}},
		system:  "You are the librarian. You answer from what you know about solar panels, Delegent, and coffee in two or three bullet points. Be brief.",
		handler: brains.Librarian,
	},
	{
		name: "mailer", port: 7102,
		skill:   a2a.Skill{ID: "send_email", Name: "Send an email", Description: "Sends an email on the company's behalf. Give the recipient, a subject, and the body.", Tags: []string{"external", "email"}, Examples: []string{"email bob@acme.example the attached summary"}},
		system:  "You are the mailer. Confirm in one sentence that the email was sent, naming the recipient.",
		handler: brains.Mailer,
	},
	{
		name: "researcher", port: 7103, caller: true, tools: []string{"__search_web", "__fetch_page", "librarian__", "mailer__"},
		skill:   a2a.Skill{ID: "research_topic", Name: "Research a topic", Description: "Researches a topic on the web and in the company archive and returns a short, sourced summary. Pass the context_id it returned to follow up in the same conversation. To email text you already have, use the mailer's send_email instead.", Tags: []string{"read", "research"}, Examples: []string{"research how Rust is used on Linux"}},
		system:  "You are the researcher at Acme. Research the user's topic: if a search_web tool is available, search the web with a focused query, then fetch_page the one or two most relevant results and cite their URLs; consult librarian__search_docs only when the topic is one its description says the archive covers. Write a short, sourced summary. ONLY if the user explicitly asks to email or send the result, call mailer__send_email with the recipient, subject and body. In a follow-up (earlier turns are in the conversation), act on what was already produced: a request to send it means send the previous summary, not research again. If asked to send or shorten something and this conversation holds no earlier result, say so and stop — do not research the request text. Always fill _delegent_intent with one sentence on why the call serves the user's request. If a tool is refused or pending, do not retry it more than once; report what happened. Finish with the summary as plain text.",
		handler: brains.Researcher,
	},
	{
		name: "assistant", port: 7104, caller: true, tools: []string{"researcher__"},
		skill:   a2a.Skill{ID: "write_report", Name: "Write a report", Description: "Prepares a report on a topic by delegating the research to the researcher agent.", Tags: []string{"read", "reports"}, Examples: []string{"write a report on coffee"}},
		system:  "You are the assistant at Acme. Delegate research to researcher__research_topic (pass the user's request as the message, and fill _delegent_intent), then present its result as a report. Do not call any other tool.",
		handler: brains.Assistant,
	},
}

func main() {
	all := flag.Bool("all", false, "run every role in this process")
	which := flag.String("role", "", "run one role: librarian | mailer | researcher | assistant")
	host := flag.String("host", "127.0.0.1", "interface to listen on")
	portBase := flag.Int("port-base", 0, "override the port block: roles get port-base+1…+4 (default 7101…7104)")
	delegent := flag.String("delegent", envOr("DELEGENT_URL", "http://127.0.0.1:8090/mcp"), "Delegent's MCP endpoint the caller roles use (env DELEGENT_URL)")
	keyDir := flag.String("key-dir", envOr("DEMO_KEY_DIR", ""), "directory holding <role>.key files with each caller's Delegent agent key (env DEMO_KEY_DIR); read at call time")
	secretPrefix := flag.String("secret-prefix", envOr("DEMO_SECRET_PREFIX", "secret-"), "each role's inbound bearer is <prefix><role> (env DEMO_SECRET_PREFIX); this is the secret you give Delegent as --credential")
	brain := flag.String("brain", envOr("DEMO_BRAIN", "scripted"), "scripted | ollama (env DEMO_BRAIN)")
	model := flag.String("model", envOr("DEMO_MODEL", "llama3.2:3b"), "Ollama model for --brain ollama (env DEMO_MODEL)")
	ollamaURL := flag.String("ollama", envOr("OLLAMA_HOST", "http://127.0.0.1:11434"), "Ollama base URL (env OLLAMA_HOST)")
	numCtx := flag.Int("num-ctx", 0, "context window to request from Ollama (0 = the server's default; set OLLAMA_CONTEXT_LENGTH on the server instead, so every client agrees and the model is never reloaded)")
	think := flag.Bool("think", false, "enable the model's thinking mode for --brain ollama (more careful tool use, much slower)")
	approvalWait := flag.Duration("approval-wait", 5*time.Minute, "how long a caller keeps retrying a call that is pending human approval")
	pace := flag.Duration("pace", envDuration("DEMO_PACE", 2*time.Second), "how long each unit of an agent's work takes (env DEMO_PACE); 0 makes the scripted agents instant")
	flag.Parse()

	var selected []role
	for _, r := range roles {
		if *all || r.name == *which {
			selected = append(selected, r)
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "pick --all or --role <librarian|mailer|researcher|assistant>")
		os.Exit(2)
	}
	if *brain != "scripted" && *brain != "ollama" {
		fmt.Fprintln(os.Stderr, "--brain must be scripted or ollama")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, r := range selected {
		r := r
		port := r.port
		if *portBase != 0 {
			for i, rr := range roles {
				if rr.name == r.name {
					port = *portBase + i + 1
				}
			}
		}
		logf := func(format string, args ...any) { log.Printf("["+r.name+"] "+format, args...) }
		deps := brains.Deps{Logf: logf, Pace: *pace}
		if r.caller {
			c := &dclient.Client{Endpoint: *delegent, ApprovalWait: *approvalWait, Logf: logf}
			if k := os.Getenv("DELEGENT_AGENT_KEY_" + strings.ToUpper(r.name)); k != "" {
				c.Key = k
			} else if *keyDir != "" {
				c.KeyFile = filepath.Join(*keyDir, r.name+".key")
			} else {
				logf("⚠️  no Delegent key: set DELEGENT_AGENT_KEY_%s or --key-dir; outbound calls will fail", strings.ToUpper(r.name))
			}
			deps.Delegent = c
		}
		var h a2aserver.Handler
		if *brain == "ollama" {
			h = brains.Ollama(deps, brains.OllamaOpts{URL: *ollamaURL, Model: *model, System: r.system, Tools: r.tools, NumCtx: *numCtx, Think: *think})
		} else {
			h = r.handler(deps)
		}
		base := fmt.Sprintf("http://%s:%d", *host, port)
		srv := &a2aserver.Server{
			Card: a2a.Card{
				Name: strings.ToUpper(r.name[:1]) + r.name[1:], Description: r.skill.Description, URL: base + "/a2a", Version: "0.1.0",
				ProtocolVersion: "0.3.0", PreferredTransport: "JSONRPC",
				Capabilities:      a2a.Capabilities{},
				DefaultInputModes: []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"},
				Skills:          []a2a.Skill{r.skill},
				SecuritySchemes: map[string]a2a.SecurityScheme{"bearer": {Type: "http", Scheme: "bearer"}},
				Security:        []map[string][]string{{"bearer": {}}},
			},
			Secret:  *secretPrefix + r.name,
			Handler: h,
			Logf:    logf,
		}
		mux := http.NewServeMux()
		srv.Routes(mux)
		hs := &http.Server{Addr: fmt.Sprintf("%s:%d", *host, port), Handler: mux}
		go func() {
			<-ctx.Done()
			_ = hs.Close()
		}()
		go func() {
			if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[%s] %v", r.name, err)
			}
		}()
		logf("up at %s (card %s%s) · skill %s · brain %s · inbound secret %q", base, base, a2a.WellKnownPath, r.skill.ID, *brain, *secretPrefix+r.name)
	}
	<-ctx.Done()
}

func envDuration(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
