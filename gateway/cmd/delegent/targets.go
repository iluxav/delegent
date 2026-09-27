package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"delegent.dev/gateway"
	"delegent.dev/gateway/a2a"
	"delegent.dev/gateway/agentkey"
	"delegent.dev/gateway/id"
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
	case "access":
		return targetAccess(args[1:])
	case "remembered":
		return targetRemembered(args[1:])
	case "disable":
		return targetSetEnabled(args[1:], false)
	default:
		return fmt.Errorf("unknown target subcommand %q (want add|list|enable|disable|access|remembered)", args[0])
	}
}

// targetAdd introspects the upstream MCP server, accepts its drafted classification as-is,
// and provisions the full wiring (adapter, advisor, sealed credential, target, entitlement)
// through the same provision core the hosted console uses. Review or tighten the stored
// classification later by editing adapters.json / entitlements.json.
func targetAdd(args []string) error {
	fs := flag.NewFlagSet("target add", flag.ExitOnError)
	home := homeFlag(fs)
	targetID := fs.String("id", "", "target id (lowercase slug; required)")
	name := fs.String("name", "", "display name (default: the id)")
	endpoint := fs.String("endpoint", "", "upstream MCP endpoint URL, or an A2A agent's base URL / agent card URL (required)")
	credential := fs.String("credential", "", "upstream bearer credential; sealed at rest (optional)")
	kind := fs.String("kind", "mcp", "what the endpoint speaks: mcp (a tool server) or a2a (an agent publishing an Agent Card)")
	mintKey := fs.Bool("mint-key", false, "a2a only: also mint the agent key this agent uses when it calls OTHER targets through delegent (printed once)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetID == "" || *endpoint == "" {
		return errors.New("--id and --endpoint are required")
	}
	if *kind != "mcp" && *kind != gateway.TargetKindA2A {
		return fmt.Errorf("--kind must be mcp or a2a, not %q", *kind)
	}
	if *mintKey && *kind != gateway.TargetKindA2A {
		return errors.New("--mint-key applies to --kind a2a targets only")
	}
	if *name == "" {
		*name = *targetID
	}
	ctx := context.Background()
	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}

	var res *introspect.Result
	if *kind == gateway.TargetKindA2A {
		fmt.Printf("fetching agent card from %s …\n", *endpoint)
		var card *a2a.Card
		res, card, err = a2a.Introspect(ctx, *endpoint, *credential)
		if err != nil {
			return fmt.Errorf("could not read the agent card (is the agent up, and does it publish %s?): %w", a2a.WellKnownPath, err)
		}
		fmt.Printf("agent %q (%s): %d skill(s), JSON-RPC at %s\n", card.Name, card.Version, len(card.Skills), card.URL)
		if ck := card.CredentialKind(); ck != "" && *credential == "" {
			fmt.Printf("⚠️  the card declares %s auth but no --credential was given; calls may be rejected\n", ck)
		}
	} else {
		fmt.Printf("introspecting %s …\n", *endpoint)
		res, err = introspect.Introspect(ctx, *endpoint, *credential)
		if err != nil {
			return fmt.Errorf("introspection failed (is the endpoint reachable and the credential valid?): %w", err)
		}
	}

	out, err := provision.CreateTarget(ctx, e.st, secretstore.NewDB(e.st, e.sealer), provision.CreateTargetInput{
		ID: *targetID, Name: *name, Kind: *kind, Endpoint: *endpoint,
		Credential: *credential, Owner: e.operator, Tools: provision.FromDraft(res.Tools),
	})
	if err != nil {
		return err
	}
	if *mintKey {
		full, hash, prefix := agentkey.New()
		if err := e.st.PutAgentKey(ctx, &store.AgentKey{
			ID: id.New("akey"), UserID: e.operator, Hash: hash, Prefix: prefix, Name: "agent:" + out.ID,
			AgentTargetID: out.ID, CreatedAt: nowMillis(),
		}); err != nil {
			return err
		}
		fmt.Printf("agent key \"agent:%s\" minted for the agent's OWN calls through delegent — shown ONCE, hand it to the agent now:\n\n  %s\n\n", out.ID, full)
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
		kind := t.Kind
		if kind == "" {
			kind = "mcp"
		}
		cred := "no credential"
		if t.CredentialRef != "" {
			cred = "sealed credential"
			if t.CredentialKind == "oauth2" {
				cred = "oauth2 credential"
			}
		}
		fmt.Printf("%-16s %-4s %-8s %-18s %s\n", t.ID, kind, state, cred, t.Endpoint)
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

// targetAccess shows or sets a target's gates and consent mode:
//
//	delegent target access <id>
//	delegent target access <id> --audience any|none|listed --uses everything|listed --consent ask|remember|allow
//
// The edges the "listed" gates read are managed with 'delegent relation'.
func targetAccess(args []string) error {
	fs := flag.NewFlagSet("target access", flag.ExitOnError)
	home := homeFlag(fs)
	audience := fs.String("audience", "", "the lock: any (default — agents may use it, each per its own --uses) or none (no agent, only your own clients)")
	uses := fs.String("uses", "", "agents only — what it may reach: everything (default) or listed (only targets it is related to)")
	consent := fs.String("consent", "", "how a permitted caller is asked: ask (every time, default), remember (ask once per caller; \"always\" is offered), allow (never for read/write)")
	if err := parseAround(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: delegent target access <id> [--audience …] [--uses …] [--consent …]")
	}
	ctx := context.Background()
	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	t, err := e.st.GetTarget(ctx, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("no target %q", fs.Arg(0))
	}
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "home" {
			set = true
		}
	})
	if set {
		aud, use, con := t.Audience, t.Uses, t.Consent
		if *audience != "" {
			v, ok := map[string]string{"any": store.AudienceEveryone, "everyone": store.AudienceEveryone, "none": store.AudienceHumans, "humans": store.AudienceHumans}[*audience]
			if !ok {
				return fmt.Errorf("--audience must be any or none")
			}
			aud = v
		}
		if *uses != "" {
			v, ok := map[string]string{"everything": store.UsesEverything, "listed": store.UsesListed}[*uses]
			if !ok {
				return fmt.Errorf("--uses must be everything or listed")
			}
			use = v
		}
		if *consent != "" {
			v, ok := map[string]string{"ask": store.ConsentAsk, "remember": store.ConsentRemember, "allow": store.ConsentAllow}[*consent]
			if !ok {
				return fmt.Errorf("--consent must be ask, remember, or allow")
			}
			con = v
		}
		if err := applyAccess(ctx, e.st, t, aud, use, con); err != nil {
			return err
		}
		fmt.Println("saved — restart serve to apply (the dashboard applies it live)")
	}
	usesRels, _ := e.st.ListRelations(ctx, t.ID, "")
	fmt.Printf("%s\n  agents: %s\n", t.ID, audienceLabel(t, seenBy(ctx, e.st, t)))
	if t.Kind == "a2a" {
		fmt.Printf("  what it can use: %s\n", usesLabel(t, usesRels))
	}
	fmt.Printf("  when to ask: %s\n", consentLabel(t.Consent))
	return nil
}

func audienceLabel(t *store.Target, sees []string) string {
	if t.Audience == store.AudienceHumans {
		return "locked — no agent (your own clients only)"
	}
	if len(sees) == 0 {
		return "may use it; none sees it yet"
	}
	return "may use it; seen by " + strings.Join(sees, ", ")
}

// seenBy lists the enabled agents that currently see t — the map read from the callee's side.
func seenBy(ctx context.Context, st store.Store, t *store.Target) []string {
	ts, _ := st.ListTargets(ctx)
	var out []string
	for _, a := range ts {
		if a.Kind == "a2a" && a.Enabled && a.ID != t.ID && store.Visible(ctx, st, &store.AgentKey{ID: "k", AgentTargetID: a.ID}, t) {
			out = append(out, a.ID)
		}
	}
	return out
}

func usesLabel(t *store.Target, rels []*store.Relation) string {
	if t.Uses != store.UsesListed {
		return "everything its callees admit it to"
	}
	var ids []string
	for _, r := range rels {
		ids = append(ids, r.Target)
	}
	if len(ids) == 0 {
		return "only related targets: (none yet — 'delegent relation add " + t.ID + " <target>')"
	}
	return "only related targets: " + strings.Join(ids, ", ")
}

func consentLabel(mode string) string {
	switch mode {
	case store.ConsentRemember:
		return "ask once per caller, then remember"
	case store.ConsentAllow:
		return "never ask for read/write (a spend always asks)"
	}
	return "ask every time"
}

// targetRemembered lists the "always" decisions on a target, or forgets one:
//
//	delegent target remembered <id> [--forget <agent-or-key-id>]
func targetRemembered(args []string) error {
	fs := flag.NewFlagSet("target remembered", flag.ExitOnError)
	home := homeFlag(fs)
	forget := fs.String("forget", "", "caller (agent id, or a person's key id) whose remembered decision to drop")
	if err := parseAround(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: delegent target remembered <id> [--forget <caller>]")
	}
	ctx := context.Background()
	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	if _, err := e.st.GetTarget(ctx, fs.Arg(0)); err != nil {
		return fmt.Errorf("no target %q", fs.Arg(0))
	}
	if *forget != "" {
		if err := e.st.DeleteRemembered(ctx, *forget, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Printf("forgotten: %s on %s — it asks again\n", *forget, fs.Arg(0))
		return nil
	}
	ps, err := e.st.ListRemembered(ctx, "", fs.Arg(0))
	if err != nil {
		return err
	}
	if len(ps) == 0 {
		fmt.Printf("%s: nothing remembered — every caller asks\n", fs.Arg(0))
		return nil
	}
	for _, p := range ps {
		name := p.Caller
		if k, err := e.st.GetAgentKey(ctx, p.Caller); err == nil {
			name = k.Name + " (" + k.ID + ")"
		} else if t, err := e.st.GetTarget(ctx, p.Caller); err == nil {
			name = "agent " + t.ID
		}
		sc := "every scope"
		if len(p.Scopes) > 0 {
			sc = strings.Join(p.Scopes, ", ")
		}
		fmt.Printf("%-40s %-30s %s\n", name, sc, p.Reason)
	}
	return nil
}

// cmdRelation manages the relationship map — the edges "agent may use target" that the
// listed gates read:
//
//	delegent relation list [<agent>]
//	delegent relation add <agent> <target>
//	delegent relation rm <agent> <target>
func cmdRelation(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: delegent relation list|add|rm …")
	}
	fs := flag.NewFlagSet("relation "+args[0], flag.ExitOnError)
	home := homeFlag(fs)
	if err := parseAround(fs, args[1:]); err != nil {
		return err
	}
	ctx := context.Background()
	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		rels, err := e.st.ListRelations(ctx, fs.Arg(0), "")
		if err != nil {
			return err
		}
		if len(rels) == 0 {
			fmt.Println("no relations — every agent sees what its callees admit it to")
			return nil
		}
		for _, r := range rels {
			fmt.Printf("%s → %s\n", r.Agent, r.Target)
		}
		return nil
	case "add", "rm":
		if fs.NArg() != 2 {
			return fmt.Errorf("usage: delegent relation %s <agent> <target>", args[0])
		}
		if err := setRelation(ctx, e.st, fs.Arg(0), fs.Arg(1), args[0] == "add"); err != nil {
			return err
		}
		if args[0] == "add" {
			fmt.Printf("%s → %s — restart serve to apply (the dashboard applies it live)\n", fs.Arg(0), fs.Arg(1))
		} else {
			fmt.Printf("removed %s → %s — restart serve to apply\n", fs.Arg(0), fs.Arg(1))
		}
		return nil
	default:
		return fmt.Errorf("unknown relation subcommand %q (want list|add|rm)", args[0])
	}
}

// parseAround parses flags that may come before, between or after positional arguments, so
// "target access librarian --consent remember" reads as naturally as the flags-first form.
func parseAround(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	// flags after the positionals: re-parse the tail, then put the positionals back
	var pos []string
	for fs.NArg() > 0 {
		rest := fs.Args()
		i := 0
		for i < len(rest) && !strings.HasPrefix(rest[i], "-") {
			pos = append(pos, rest[i])
			i++
		}
		if i == len(rest) {
			break
		}
		if err := fs.Parse(rest[i:]); err != nil {
			return err
		}
	}
	return fs.Parse(pos)
}
