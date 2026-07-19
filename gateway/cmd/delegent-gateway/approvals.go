package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// adminCall hits the /admin surface of the running serve process with the config admin token.
func adminCall(e *env, method, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, "http://"+e.cfg.ListenAddr+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the gateway at %s — is 'delegent-gateway serve' running? (%v)", e.cfg.ListenAddr, err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func cmdApprovals(args []string) error {
	if len(args) > 0 && (args[0] == "approve" || args[0] == "deny") {
		return approvalsResolve(args[0], args[1:])
	}
	return approvalsList(args)
}

func approvalsList(args []string) error {
	fs := flag.NewFlagSet("approvals", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := requireOperator(context.Background(), *home)
	if err != nil {
		return err
	}
	var out struct {
		Live   []gateway.PendingView   `json:"live"`
		Parked []*store.ConsentRequest `json:"parked"`
	}
	if err := adminCall(e, http.MethodGet, "/admin/consents", nil, &out); err != nil {
		return err
	}
	if len(out.Live)+len(out.Parked) == 0 {
		fmt.Println("no pending approvals")
		return nil
	}
	for _, p := range out.Live {
		scopes := make([]string, 0, len(p.Scopes))
		for _, sc := range p.Scopes {
			scopes = append(scopes, sc.Scope)
		}
		line := p.Headline
		if line == "" {
			line = strings.Join(scopes, " ")
		}
		fmt.Printf("%-14s LIVE     %-12s %s — %s\n", p.ID, p.AgentName, p.TargetID, line)
		if p.Intent != "" {
			fmt.Printf("%14s          agent's why: %s\n", "", p.Intent)
		}
		for _, warn := range p.OverAskWarnings {
			fmt.Printf("%14s          ⚠️ %s\n", "", warn)
		}
	}
	for _, p := range out.Parked {
		line := p.Headline
		if line == "" {
			line = strings.Join(p.Scopes, " ")
		}
		fmt.Printf("%-14s parked   %-12s %s — %s\n", p.ID, p.AgentName, p.TargetID, line)
	}
	fmt.Println("\nresolve with: delegent-gateway approvals approve|deny <id> [--scopes a,b] [--ttl 60]")
	return nil
}

func approvalsResolve(verb string, args []string) error {
	fs := flag.NewFlagSet("approvals "+verb, flag.ExitOnError)
	home := homeFlag(fs)
	scopes := fs.String("scopes", "", "approve only these comma-separated scopes (default: all requested)")
	ttl := fs.Int("ttl", 0, "grant lifetime in minutes (0 = the gateway default)")
	budget := fs.Float64("budget", 0, "spend ceiling in USD (0 = none)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: delegent-gateway approvals %s <id>", verb)
	}
	e, err := requireOperator(context.Background(), *home)
	if err != nil {
		return err
	}

	req := resolveReq{Approve: verb == "approve", TTLMinutes: *ttl, BudgetUSD: *budget}
	if *scopes != "" {
		req.Scopes = strings.Split(*scopes, ",")
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := adminCall(e, http.MethodPost, "/admin/consents/"+fs.Arg(0), req, &out); err != nil {
		return err
	}
	if !out.OK {
		return errors.New("no live ask holds that id — it expired, was already resolved, or the agent gave up (a parked row was reconciled; the agent re-asks on its next call)")
	}
	fmt.Printf("%sd %s\n", verb, fs.Arg(0))
	return nil
}

func cmdTelegram(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: delegent-gateway telegram setup|link [flags]")
	}
	switch args[0] {
	case "setup":
		return telegramSetupCmd(args[1:])
	case "link":
		return telegramLinkCmd(args[1:])
	default:
		return fmt.Errorf("unknown telegram subcommand %q (want setup|link)", args[0])
	}
}

func telegramSetupCmd(args []string) error {
	fs := flag.NewFlagSet("telegram setup", flag.ExitOnError)
	home := homeFlag(fs)
	token := fs.String("token", "", "bot token from @BotFather (required)")
	botUsername := fs.String("bot-username", "", "the bot's @username (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *botUsername == "" {
		return errors.New("--token and --bot-username are required")
	}
	e, err := requireOperator(context.Background(), *home)
	if err != nil {
		return err
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := adminCall(e, http.MethodPost, "/admin/telegram", telegramSetupReq{Token: *token, BotUsername: *botUsername}, &out); err != nil {
		return err
	}
	fmt.Println(out.Status + " — now run 'delegent-gateway telegram link' to bind your chat")
	return nil
}

func telegramLinkCmd(args []string) error {
	fs := flag.NewFlagSet("telegram link", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	e, err := requireOperator(context.Background(), *home)
	if err != nil {
		return err
	}
	var out struct {
		Token       string `json:"token"`
		BotUsername string `json:"bot_username"`
	}
	if err := adminCall(e, http.MethodPost, "/admin/telegram/link", nil, &out); err != nil {
		return err
	}
	bot := out.BotUsername
	if bot == "" {
		bot = "your bot"
	}
	fmt.Printf("open a chat with @%s and send (within 10 minutes):\n\n  /start %s\n\n", bot, out.Token)
	return nil
}
