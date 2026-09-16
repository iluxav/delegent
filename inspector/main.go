// Command mcp-inspector is a single-binary web UI for poking at MCP servers: paste an
// mcpServers block (the Claude Desktop / Claude Code / Cursor shape), connect over stdio or
// HTTP, list and call tools, read resources, get prompts, answer elicitations, and watch
// every message in both directions in a live transcript.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// version is stamped with -ldflags "-X main.version=…"; "dev" for a plain go build.
var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:8095", "listen address")
	config := flag.String("config", DefaultConfigPath(), "file the pasted servers config is saved to")
	flag.Parse()
	log.SetFlags(log.Ltime)

	m := NewManager(*config)
	if err := m.LoadFile(); err != nil {
		log.Printf("ignoring %s: %v", *config, err)
	}
	a, err := newApp(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-inspector:", err)
		os.Exit(1)
	}
	srv := &http.Server{Addr: *addr, Handler: a.routes()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		m.Close() // stops stdio children and closes HTTP sessions
	}()

	log.Printf("mcp-inspector %s listening on http://%s (servers config: %s)", version, *addr, *config)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "mcp-inspector:", err)
		os.Exit(1)
	}
}
