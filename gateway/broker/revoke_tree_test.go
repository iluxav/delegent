package broker_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"delegent.dev/gateway/store"
)

// RevokeTree revokes a whole run: the root and every live session it delegated to, however
// deep, and reports them. A branch revoked earlier and a session outside the tree are left as
// they are.
func TestRevokeTree(t *testing.T) {
	b, st := nameBroker(t)
	putSess(t, st, "root", "")
	putSess(t, st, "pm", "root")
	putSess(t, st, "engineer", "pm")
	putSess(t, st, "qa", "engineer")
	putSess(t, st, "other", "")
	if err := st.PutSession(context.Background(), &store.Session{Handle: "gone", Principal: "root:alice", ParentHandle: "pm", RevokedAt: 5}); err != nil {
		t.Fatal(err)
	}

	handles, revoked := b.RevokeTree("root")
	sort.Strings(handles)
	if got := strings.Join(handles, ","); got != "engineer,pm,qa,root" {
		t.Errorf("handles = %s", got)
	}
	if revoked != 4 {
		t.Errorf("revoked %d, want 4", revoked)
	}
	for _, h := range []string{"root", "pm", "engineer", "qa"} {
		if ss, _ := st.GetSession(context.Background(), h); ss.RevokedAt == 0 {
			t.Errorf("%s still live", h)
		}
	}
	if ss, _ := st.GetSession(context.Background(), "other"); ss.RevokedAt != 0 {
		t.Error("a session outside the run was revoked")
	}
	if handles, revoked := b.RevokeTree("nope"); len(handles) != 0 || revoked != 0 {
		t.Errorf("unknown root: %v %d", handles, revoked)
	}
}
