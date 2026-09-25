package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/id"
	"delegent.dev/gateway/store"
)

func cmdKey(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: delegent key mint|list|revoke [flags]")
	}
	switch args[0] {
	case "mint":
		return keyMint(args[1:])
	case "list":
		return keyList(args[1:])
	case "revoke":
		return keyRevoke(args[1:])
	default:
		return fmt.Errorf("unknown key subcommand %q (want mint|list|revoke)", args[0])
	}
}

func keyMint(args []string) error {
	fs := flag.NewFlagSet("key mint", flag.ExitOnError)
	home := homeFlag(fs)
	name := fs.String("name", "", "key name — the durable label events aggregate by (required unless --agent)")
	agent := fs.String("agent", "", "issue the key to a fronted A2A agent (target id): the key it uses when it calls other targets through delegent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" && *agent != "" {
		*name = "agent:" + *agent
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}

	if *agent != "" {
		t, err := e.st.GetTarget(ctx, *agent)
		if err != nil {
			return fmt.Errorf("--agent: no target %q", *agent)
		}
		if t.Kind != "a2a" {
			return fmt.Errorf("--agent: target %q is an MCP server, not an agent", *agent)
		}
	}
	full, hash, prefix := agentkey.New()
	if err := e.st.PutAgentKey(ctx, &store.AgentKey{
		ID: id.New("akey"), UserID: e.operator, Hash: hash, Prefix: prefix, Name: *name, AgentTargetID: *agent, CreatedAt: nowMillis(),
	}); err != nil {
		return err
	}
	fmt.Printf("agent key %q minted — shown ONCE, store it now:\n\n  %s\n\n", *name, full)
	return nil
}

func keyList(args []string) error {
	fs := flag.NewFlagSet("key list", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}
	keys, err := e.st.ListAgentKeys(ctx, e.operator)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no agent keys — mint one with 'delegent key mint --name <name>'")
		return nil
	}
	for _, k := range keys {
		state := "active"
		if k.RevokedAt != 0 {
			state = "REVOKED"
		}
		last := "never used"
		if k.LastUsedAt != 0 {
			last = "last used " + time.UnixMilli(k.LastUsedAt).Format(time.RFC3339)
		}
		fmt.Printf("%-24s %-12s %-8s %-10s %s\n", k.ID, k.Prefix+"…", state, k.Name, last)
	}
	return nil
}

func keyRevoke(args []string) error {
	fs := flag.NewFlagSet("key revoke", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: delegent key revoke <akey_id>")
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}
	if err := e.st.RevokeAgentKey(ctx, fs.Arg(0), nowMillis()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no key %q", fs.Arg(0))
		}
		return err
	}
	fmt.Printf("key %s revoked — restart serve to apply\n", fs.Arg(0))
	return nil
}
