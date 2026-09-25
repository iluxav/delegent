// demo-call is a shell harness for the walkthrough: it plays the role Claude Code plays —
// a consumer with a Delegent key calling one tool — so the chain can be exercised without a
// chat client. It prints the tool's text result. Consent for a harness with no elicitation
// lands in the console: approve it in the dashboard or with `delegent approvals`, and this
// command keeps retrying meanwhile.
//
//	demo-call --key dgk_… researcher__research_topic '{"message":"research solar panels"}'
//	demo-call --key dgk_… --list
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"delegent.dev/agents/internal/dclient"
)

func main() {
	endpoint := flag.String("delegent", envOr("DELEGENT_URL", "http://127.0.0.1:8090/mcp"), "Delegent's MCP endpoint (env DELEGENT_URL)")
	key := flag.String("key", os.Getenv("DELEGENT_AGENT_KEY"), "agent key (env DELEGENT_AGENT_KEY)")
	keyFile := flag.String("key-file", "", "file holding the agent key")
	session := flag.String("session", "", "act UNDER this Delegent session (what an agent echoes); empty = a root call")
	intent := flag.String("intent", "", "the _delegent_intent to declare on the call")
	list := flag.Bool("list", false, "list the vendor tools instead of calling one")
	wait := flag.Duration("approval-wait", 5*time.Minute, "how long to keep retrying while consent is pending")
	flag.Parse()

	c := &dclient.Client{Endpoint: *endpoint, Key: *key, KeyFile: *keyFile, ApprovalWait: *wait, Logf: log.Printf}
	ctx := context.Background()
	s, err := c.Open(ctx, *session)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	if *list {
		tools, err := s.Tools(ctx)
		if err != nil {
			log.Fatal(err)
		}
		for _, t := range tools {
			fmt.Printf("%-32s %s\n", t.Name, t.Description)
		}
		return
	}
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: demo-call [flags] <tool> [json-args]")
		os.Exit(2)
	}
	args := map[string]any{}
	if flag.NArg() > 1 {
		if err := json.Unmarshal([]byte(flag.Arg(1)), &args); err != nil {
			log.Fatalf("args must be a JSON object: %v", err)
		}
	}
	out, err := s.Call(ctx, flag.Arg(0), args, *intent, func(line string) { log.Print(line) })
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
