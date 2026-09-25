package main

import (
	"strings"
	"testing"
)

func TestHermesYAML(t *testing.T) {
	got := hermesYAML(map[string]string{"url": "http://127.0.0.1:8090/mcp"}, map[string]string{"Authorization": "Bearer dgk_x"}, nil)
	want := "mcp_servers:\n  delegent:\n    url: \"http://127.0.0.1:8090/mcp\"\n    headers:\n      Authorization: \"Bearer dgk_x\""
	if got != want {
		t.Errorf("remote yaml:\n%s\nwant:\n%s", got, want)
	}
	got = hermesYAML(map[string]string{"command": "/usr/local/bin/delegent"}, nil, map[string]string{"DELEGENT_AGENT_KEY": "dgk_x", "DELEGENT_HOME": "/h o/me"})
	for _, frag := range []string{"command: \"/usr/local/bin/delegent\"", "args: [\"stdio\"]", "env:\n      DELEGENT_AGENT_KEY: \"dgk_x\"\n      DELEGENT_HOME: \"/h o/me\""} {
		if !strings.Contains(got, frag) {
			t.Errorf("stdio yaml missing %q:\n%s", frag, got)
		}
	}
}
