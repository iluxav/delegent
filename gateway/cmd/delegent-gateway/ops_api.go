package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"delegent.dev/gateway"
	"delegent.dev/gateway/introspect"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/store"
)

// apiOps drives a LIVE gateway process through its /admin surface — full features including
// the SSE consent stream and live-applied edits (the process invalidates its gateways).
type apiOps struct {
	base   string // http://host:port
	token  string
	label  string // "live: stdio pid 4711"
	client *http.Client
}

func newAPIOps(addr, token, label string) *apiOps {
	return &apiOps{base: "http://" + addr, token: token, label: label,
		client: &http.Client{Timeout: 30 * time.Second}}
}

func (a *apiOps) Mode() string { return a.label }
func (a *apiOps) Close() error { return nil }

func (a *apiOps) do(ctx context.Context, method, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway unreachable: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&e)
		if e.Error == "" {
			e.Error = res.Status
		}
		if res.StatusCode == http.StatusNotFound {
			return store.ErrNotFound
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (a *apiOps) ListTargets(ctx context.Context) ([]targetRow, error) {
	var out []targetRow
	return out, a.do(ctx, http.MethodGet, "/admin/targets", nil, &out)
}

func (a *apiOps) TargetDetail(ctx context.Context, id string) (*targetDetail, error) {
	var out targetDetail
	if err := a.do(ctx, http.MethodGet, "/admin/targets/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *apiOps) PutPolicy(ctx context.Context, id, name string, tools []provision.ToolSpec) error {
	return a.do(ctx, http.MethodPut, "/admin/targets/"+url.PathEscape(id)+"/policy", putPolicyReq{Name: name, Tools: tools}, nil)
}

func (a *apiOps) SetTargetEnabled(ctx context.Context, id string, enabled bool) error {
	return a.do(ctx, http.MethodPut, "/admin/targets/"+url.PathEscape(id)+"/enabled", map[string]bool{"enabled": enabled}, nil)
}

func (a *apiOps) Introspect(ctx context.Context, id string) (*introspect.Result, error) {
	var out introspect.Result
	if err := a.do(ctx, http.MethodPost, "/admin/targets/"+url.PathEscape(id)+"/introspect", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *apiOps) SetDisabled(ctx context.Context, targetID string, disabled []string) (*entitlementView, error) {
	var out entitlementView
	if err := a.do(ctx, http.MethodPut, "/admin/entitlements/"+url.PathEscape(targetID), map[string][]string{"disabled": disabled}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *apiOps) ListKeys(ctx context.Context) ([]keyRow, error) {
	var out []keyRow
	return out, a.do(ctx, http.MethodGet, "/admin/keys", nil, &out)
}

type keyMintResp struct {
	Key       keyRow `json:"key"`
	Plaintext string `json:"plaintext"`
}

func (a *apiOps) MintKey(ctx context.Context, name string) (keyRow, string, error) {
	var out keyMintResp
	if err := a.do(ctx, http.MethodPost, "/admin/keys", map[string]string{"name": name}, &out); err != nil {
		return keyRow{}, "", err
	}
	return out.Key, out.Plaintext, nil
}

func (a *apiOps) RevokeKey(ctx context.Context, id string) error {
	return a.do(ctx, http.MethodPost, "/admin/keys/"+url.PathEscape(id)+"/revoke", nil, nil)
}

func (a *apiOps) RollKey(ctx context.Context, id string) (keyRow, string, error) {
	var out keyMintResp
	if err := a.do(ctx, http.MethodPost, "/admin/keys/"+url.PathEscape(id)+"/roll", nil, &out); err != nil {
		return keyRow{}, "", err
	}
	return out.Key, out.Plaintext, nil
}

func (a *apiOps) ListEvents(ctx context.Context, f store.EventFilter) ([]*store.Event, error) {
	q := url.Values{}
	if f.KeyName != "" {
		q.Set("key_name", f.KeyName)
	}
	if f.Type != "" {
		q.Set("type", f.Type)
	}
	if f.TargetID != "" {
		q.Set("target", f.TargetID)
	}
	if f.Tool != "" {
		q.Set("tool", f.Tool)
	}
	if f.Decision != "" {
		q.Set("decision", f.Decision)
	}
	if f.Limit > 0 {
		q.Set("limit", fmt.Sprint(f.Limit))
	}
	var out []*store.Event
	return out, a.do(ctx, http.MethodGet, "/admin/events?"+q.Encode(), nil, &out)
}

func (a *apiOps) Consents(ctx context.Context) (*consentBundle, error) {
	var out consentBundle
	if err := a.do(ctx, http.MethodGet, "/admin/consents", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *apiOps) Resolve(ctx context.Context, id string, approve bool, scopes []string, ttlMinutes int, budgetUSD float64) (bool, error) {
	var out struct {
		OK bool `json:"ok"`
	}
	err := a.do(ctx, http.MethodPost, "/admin/consents/"+url.PathEscape(id),
		resolveReq{Approve: approve, Scopes: scopes, TTLMinutes: ttlMinutes, BudgetUSD: budgetUSD}, &out)
	return out.OK, err
}

// StreamConsents opens the SSE stream and parses `data:` lines into ConsentEvents. The
// channel closes when the stream drops — the dashboard treats that as "reconnect".
func (a *apiOps) StreamConsents(ctx context.Context) (<-chan gateway.ConsentEvent, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+"/admin/consents/stream", nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	// no client timeout on a stream — lifetime is the ctx
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("gateway unreachable: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		cancel()
		return nil, nil, fmt.Errorf("stream refused: %s", res.Status)
	}

	ch := make(chan gateway.ConsentEvent, 16)
	go func() {
		defer close(ch)
		defer res.Body.Close()
		sc := bufio.NewScanner(res.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue // comments/pings/blank separators
			}
			var ev gateway.ConsentEvent
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev) == nil {
				select {
				case ch <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return ch, cancel, nil
}
