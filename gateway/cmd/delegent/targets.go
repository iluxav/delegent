package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/secretstore"
	"delegent.dev/gateway/store"
)

func cmdTarget(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: delegent target add|list|enable|disable [flags]")
	}
	switch args[0] {
	case "add":
		return targetAdd(args[1:])
	case "list":
		return targetList(args[1:])
	case "enable":
		return targetSetEnabled(args[1:], true)
	case "disable":
		return targetSetEnabled(args[1:], false)
	default:
		return fmt.Errorf("unknown target subcommand %q (want add|list|enable|disable)", args[0])
	}
}

// targetAdd introspects the upstream MCP server, accepts its drafted classification as-is,
// and provisions the full wiring (adapter, advisor, sealed credential, target, entitlement)
// through the same provision core the hosted console uses. Review or tighten the stored
// classification later by editing adapters.json / entitlements.json.
func targetAdd(args []string) error {
	fs := flag.NewFlagSet("target add", flag.ExitOnError)
	home := homeFlag(fs)
	id := fs.String("id", "", "target id (lowercase slug; required)")
	name := fs.String("name", "", "display name (default: the id)")
	endpoint := fs.String("endpoint", "", "upstream MCP endpoint URL (required)")
	credential := fs.String("credential", "", "upstream bearer credential; sealed at rest (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *endpoint == "" {
		return errors.New("--id and --endpoint are required")
	}
	if *name == "" {
		*name = *id
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}

	fmt.Printf("introspecting %s …\n", *endpoint)
	res, err := introspect.Introspect(ctx, *endpoint, *credential)
	if err != nil {
		return fmt.Errorf("introspection failed (is the endpoint reachable and the credential valid?): %w", err)
	}

	out, err := provision.CreateTarget(ctx, e.st, secretstore.NewDB(e.st, e.sealer), provision.CreateTargetInput{
		ID: *id, Name: *name, Kind: "mcp", Endpoint: *endpoint,
		Credential: *credential, Owner: e.operator, Tools: provision.FromDraft(res.Tools),
	})
	if err != nil {
		return err
	}

	unknown := 0
	for _, t := range res.Tools {
		if t.Unknown || provision.IsUnknown(t.Effect) {
			unknown++
		}
	}
	fmt.Printf("target %s created: %d tools, scopes %s\n", out.ID, out.Tools, strings.Join(out.Scopes, " "))
	if unknown > 0 {
		fmt.Printf("⚠️  %d tool(s) could not be classified and will be REFUSED until classified in adapters.json\n", unknown)
	}
	fmt.Println("restart serve (or your MCP client, for stdio) to pick the new target up")
	return nil
}

func targetList(args []string) error {
	fs := flag.NewFlagSet("target list", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	ts, err := e.st.ListTargets(ctx)
	if err != nil {
		return err
	}
	if len(ts) == 0 {
		fmt.Println("no targets — add one with 'delegent target add'")
		return nil
	}
	for _, t := range ts {
		state := "enabled"
		if !t.Enabled {
			state = "DISABLED"
		}
		cred := "no credential"
		if t.CredentialRef != "" {
			cred = "sealed credential"
			if t.CredentialKind == "oauth2" {
				cred = "oauth2 credential"
			}
		}
		fmt.Printf("%-16s %-8s %-18s %s\n", t.ID, state, cred, t.Endpoint)
	}
	return nil
}

func targetSetEnabled(args []string, enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	fs := flag.NewFlagSet("target "+verb, flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: delegent target %s <id>", verb)
	}
	ctx := context.Background()
	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	t, err := e.st.GetTarget(ctx, fs.Arg(0))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no target %q", fs.Arg(0))
		}
		return err
	}
	t.Enabled = enabled
	if err := e.st.PutTarget(ctx, t); err != nil {
		return err
	}
	fmt.Printf("target %s %sd — restart serve to apply\n", t.ID, verb)
	return nil
}
