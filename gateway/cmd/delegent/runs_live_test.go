package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"delegent.dev/gateway/store"
)

// TestRunsPagesFromLocalLog replays a real activity log through the dashboard and fetches
// every run page, to catch data-dependent rendering failures. Env-gated like TestRunsPreview.
func TestRunsPagesFromLocalLog(t *testing.T) {
	in := os.Getenv("DELEGENT_EVENTS_FILE")
	if in == "" {
		t.Skip("set DELEGENT_EVENTS_FILE")
	}
	ts, e, logs := newDashboard(t)
	c := browser(t)
	get(t, c, ts.URL+"/setup")
	code := codeRE.FindStringSubmatch(logs.String())[1]
	post(t, c, ts.URL+"/setup", url.Values{"code": {code}, "username": {"op"}, "password": {"longenough"}, "confirm": {"longenough"}}, false)
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n := 0
	for sc.Scan() {
		var x store.Event
		if json.Unmarshal(sc.Bytes(), &x) != nil {
			continue
		}
		x.UserID = e.operator
		if err := e.st.AppendEvent(context.Background(), &x); err != nil {
			t.Fatal(err)
		}
		n++
	}
	status, body := get(t, c, ts.URL+"/runs")
	links := regexp.MustCompile(`href="(/runs/[^"]+)"`).FindAllStringSubmatch(body, -1)
	t.Logf("%d events, list status %d, %d run links", n, status, len(links))
	for _, l := range links {
		st, body := get(t, c, ts.URL+l[1])
		if st != 200 || strings.Contains(body, "template error") {
			t.Errorf("%s: status %d: %s", l[1], st, body[:min(len(body), 400)])
		}
	}
}
