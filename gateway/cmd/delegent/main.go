// Command delegent is the local, single-operator Delegent gateway: the same
// consent/authority engine the hosted product runs, self-contained in one binary — no
// database, no accounts, state in plain JSON files under one directory.
//
// Two front doors serve the identical aggregate MCP surface (every enabled target's tools,
// namespaced <target>__<tool>, consent and entitlements enforced per target):
//
//	delegent serve    HTTP  — /mcp for agents, /mcp/{target} for pinning, /admin for the CLI
//	delegent stdio    stdio — for MCP clients that launch local servers (Claude, Cursor, …)
//
// Everything lives under the home directory (default ~/.delegent, override with --home or
// DELEGENT_HOME). Secrets are sealed with a 32-byte master key read from DELEGENT_MASTER_KEY
// (base64) or <home>/master.key — `init` generates one.
package main

import (
	"fmt"
	"os"
)

// version is stamped via -ldflags "-X main.version=…"; "dev" for plain go build/install.
var version = "dev"

const usage = `usage: delegent <command> [flags]

commands:
  init                         create the home dir, master key, operator identity
  serve                        serve the gateway over HTTP (/mcp + /admin)
  stdio                        serve the gateway over stdin/stdout (MCP stdio transport)
  dashboard                    terminal dashboard: policy, scopes, keys, audit, live approvals
  target add|list|enable|disable   manage fronted MCP targets
  key mint|list|revoke         manage agent keys
  approvals [approve|deny]     list / resolve pending consent asks (talks to a running serve)
  telegram setup|link          configure telegram approvals (talks to a running serve)
  version                      print the build version

Run 'delegent <command> -h' for that command's flags. State edited by target/key
commands is read at startup: restart serve (or your MCP client, for stdio) to pick changes up.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "stdio":
		err = cmdStdio(os.Args[2:])
	case "dashboard":
		err = cmdDashboard(os.Args[2:])
	case "target":
		err = cmdTarget(os.Args[2:])
	case "key":
		err = cmdKey(os.Args[2:])
	case "approvals":
		err = cmdApprovals(os.Args[2:])
	case "telegram":
		err = cmdTelegram(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "delegent: %v\n", err)
		os.Exit(1)
	}
}
