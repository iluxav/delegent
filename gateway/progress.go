package gateway

// MCP progress plumbing for consent waits: a call that supplied a progressToken gets live
// "waiting for human approval" notifications while it blocks, so the client can show WHY
// nothing is happening instead of an opaque hang. Requests without a token get a no-op —
// per spec, progress may only flow for requests that asked for it.

import (
	"context"
	"log"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type progressFnKey struct{}

// withCallProgress derives a context carrying a progress emitter bound to this request's
// token and session. Installed at every guarded-call entry (vendor proxy, request_access,
// the widget dialog) so the consent core can report waits without knowing about MCP.
func withCallProgress(ctx context.Context, req *mcp.CallToolRequest) context.Context {
	if req == nil || req.Session == nil {
		return ctx
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return ctx
	}
	ss := req.Session
	var n atomic.Int64 // the spec requires progress to increase on every notification
	return context.WithValue(ctx, progressFnKey{}, func(message string) {
		if err := ss.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      float64(n.Add(1)),
			Message:       message,
		}); err != nil {
			log.Printf("[delegent] progress notification dropped: %v", err)
		}
	})
}

// withProgressFn installs an emitter directly — the test seam.
func withProgressFn(ctx context.Context, fn func(string)) context.Context {
	return context.WithValue(ctx, progressFnKey{}, fn)
}

// emitProgress sends one progress message for the current call, if it asked for progress.
func emitProgress(ctx context.Context, message string) {
	if fn, ok := ctx.Value(progressFnKey{}).(func(string)); ok && fn != nil {
		fn(message)
	}
}
