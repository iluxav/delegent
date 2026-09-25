package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/store"
)

// TestRunsServeLocal stands a throwaway dashboard up on DELEGENT_RUNS_SERVE_ADDR with a real
// activity log replayed into it, completes setup as op / longenough, and keeps it up for
// DELEGENT_RUNS_SERVE_SECS — a manual harness for eyeballing the live views in a browser.
func TestRunsServeLocal(t *testing.T) {
	addr, in := os.Getenv("DELEGENT_RUNS_SERVE_ADDR"), os.Getenv("DELEGENT_EVENTS_FILE")
	if addr == "" || in == "" {
		t.Skip("set DELEGENT_RUNS_SERVE_ADDR and DELEGENT_EVENTS_FILE")
	}
	secs, _ := strconv.Atoi(os.Getenv("DELEGENT_RUNS_SERVE_SECS"))
	if secs == 0 {
		secs = 180
	}
	t.Setenv("DELEGENT_MASTER_KEY", "")
	home := t.TempDir()
	if err := cmdInit([]string{"--home", home}); err != nil {
		t.Fatal(err)
	}
	e, err := requireOperator(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	mux := http.NewServeMux()
	if err := mountWeb(mux, e, gateway.NewRegistry(e.st, e.sealer)); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = http.Serve(ln, mux) }()
	base := "http://" + addr
	c := browser(t)
	get(t, c, base+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, base+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)

	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var x store.Event
		if json.Unmarshal(sc.Bytes(), &x) != nil {
			continue
		}
		x.UserID = e.operator
		_ = e.st.AppendEvent(context.Background(), &x)
	}
	fmt.Printf("SERVING %s (login op / longenough) for %ds\n", base, secs)
	time.Sleep(time.Duration(secs) * time.Second)
}
