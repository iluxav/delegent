package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// cmdDashboard runs the TUI: discover a live gateway process via runfiles (serve or stdio —
// both expose /admin on loopback), fall back to direct file editing when nothing runs.
func cmdDashboard(args []string) error {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	home := homeFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	log.SetOutput(os.Stderr)
	ctx := context.Background()

	e, err := requireOperator(ctx, *home)
	if err != nil {
		return err
	}

	var o ops
	if info, ok := discoverLive(e); ok {
		o = newAPIOps(info.AdminAddr, e.cfg.AdminToken, fmt.Sprintf("live: %s pid %d", info.Mode, info.PID))
		_ = e.st.Close() // the live process owns the files; drop our handle
	} else {
		o = newFileOps(e)
	}
	defer o.Close()

	p := tea.NewProgram(newRootModel(o), tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// discoverLive pings runfile-registered admin addresses (newest first) and returns the first
// that answers with the operator's admin token.
func discoverLive(e *env) (runInfo, bool) {
	client := &http.Client{Timeout: 800 * time.Millisecond}
	for _, info := range liveRunfiles(e.home) {
		req, err := http.NewRequest(http.MethodGet, "http://"+info.AdminAddr+"/admin/health", nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+e.cfg.AdminToken)
		res, err := client.Do(req)
		if err != nil {
			continue
		}
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			return info, true
		}
	}
	return runInfo{}, false
}
