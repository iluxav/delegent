package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// runInfo is one live gateway process's registration: written to <home>/run/<pid>.json on
// start, removed on clean exit. The dashboard discovers live instances by reading this
// directory and pinging each admin address — a runfile is a HINT, not proof of life: stale
// files (crashes, SIGKILL) are expected and filtered by the ping.
type runInfo struct {
	PID       int    `json:"pid"`
	AdminAddr string `json:"admin_addr"` // loopback host:port of the /admin surface
	Mode      string `json:"mode"`       // "serve" | "stdio"
	StartedAt int64  `json:"started_at"` // unix ms
}

func runDir(home string) string { return filepath.Join(home, "run") }

// writeRunfile registers this process and returns its cleanup. Cleanup is idempotent.
func writeRunfile(home, adminAddr, mode string) (func(), error) {
	dir := runDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	info := runInfo{PID: os.Getpid(), AdminAddr: adminAddr, Mode: mode, StartedAt: nowMillis()}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, jsonName(info.PID))
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

func jsonName(pid int) string {
	return "gw-" + itoa(pid) + ".json"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// liveRunfiles returns registrations newest-first, dropping entries whose process is
// definitively gone (signal-0 probe). Entries that survive still need an admin ping to be
// trusted — the pid may have been recycled.
func liveRunfiles(home string) []runInfo {
	entries, err := os.ReadDir(runDir(home))
	if err != nil {
		return nil
	}
	var out []runInfo
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(runDir(home), ent.Name()))
		if err != nil {
			continue
		}
		var info runInfo
		if json.Unmarshal(raw, &info) != nil || info.AdminAddr == "" {
			continue
		}
		if info.PID > 0 && syscall.Kill(info.PID, 0) != nil {
			_ = os.Remove(filepath.Join(runDir(home), ent.Name())) // stale: reap it
			continue
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	return out
}
