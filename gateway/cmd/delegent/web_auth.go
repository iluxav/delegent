package main

// Dashboard authentication. Runs locally, so it bootstraps from the terminal: the first
// visit to /setup makes serve print a one-time code; whoever can read that terminal proves
// they own the machine, picks a username and password, and .auth is written. The file is
// sealed with the instance master key (already random per machine) and holds a PBKDF2 hash,
// never the password, plus a random key that signs session cookies so logins survive restarts.

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"delegent.dev/gateway/keyring"
)

const (
	authFile      = ".auth"
	sessionCookie = "delegent_session"
	sessionTTL    = 7 * 24 * time.Hour
	pbkdf2Iters   = 600_000
	setupMaxTries = 5
)

type authRecord struct {
	Username   string `json:"username"`
	Salt       []byte `json:"salt"`
	Hash       []byte `json:"hash"`
	Iterations int    `json:"iterations"`
	SessionKey []byte `json:"session_key"`
	CreatedAt  int64  `json:"created_at"`
}

type webAuth struct {
	path   string
	sealer keyring.Sealer
	addr   string

	mu    sync.Mutex
	rec   *authRecord // nil until setup completes
	code  string      // pending one-time setup code
	tries int
}

func newWebAuth(e *env) (*webAuth, error) {
	a := &webAuth{path: filepath.Join(e.home, authFile), sealer: e.sealer, addr: e.cfg.ListenAddr}
	raw, err := os.ReadFile(a.path)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: not base64", authFile)
	}
	plain, err := e.sealer.Unseal(sealed)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot unseal — was the master key replaced? delete the file to set up again: %w", authFile, err)
	}
	var rec authRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", authFile, err)
	}
	a.rec = &rec
	return a, nil
}

func (a *webAuth) configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rec != nil
}

// setupCode returns the pending code, minting and printing one if there is none.
func (a *webAuth) setupCode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.code == "" {
		a.code = newSetupCode()
		a.tries = 0
		a.announce()
	}
	return a.code
}

func (a *webAuth) announce() {
	log.Printf("[delegent] dashboard setup — enter this code in the browser: %s   (http://%s/setup)", a.code, a.addr)
}

func newSetupCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// completeSetup checks the code and writes .auth. Five wrong codes mint a fresh one, so a
// guess cannot be brute-forced off a single printed value.
func (a *webAuth) completeSetup(code, username, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rec != nil {
		return errors.New("the dashboard is already set up — sign in instead")
	}
	if a.code == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(a.code)) != 1 {
		a.tries++
		if a.tries >= setupMaxTries {
			a.code = newSetupCode()
			a.tries = 0
			a.announce()
			return errors.New("wrong code too many times — a new code was printed in the terminal")
		}
		return errors.New("wrong code — it is printed in the terminal running delegent serve")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("choose a username")
	}
	if len(password) < 8 {
		return errors.New("use a password of at least 8 characters")
	}
	salt, key := randomBytes(16), randomBytes(32)
	hash, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iters, 32)
	if err != nil {
		return err
	}
	rec := authRecord{Username: username, Salt: salt, Hash: hash, Iterations: pbkdf2Iters, SessionKey: key, CreatedAt: nowMillis()}
	plain, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sealed, err := a.sealer.Seal(plain)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.path, []byte(base64.StdEncoding.EncodeToString(sealed)+"\n"), 0o600); err != nil {
		return err
	}
	a.rec = &rec
	a.code = ""
	log.Printf("[delegent] dashboard set up for %q → %s", username, a.path)
	return nil
}

// login is constant-time on both fields; the hash is always computed so a wrong username
// costs the same as a wrong password.
func (a *webAuth) login(username, password string) bool {
	a.mu.Lock()
	rec := a.rec
	a.mu.Unlock()
	if rec == nil {
		return false
	}
	hash, err := pbkdf2.Key(sha256.New, password, rec.Salt, rec.Iterations, len(rec.Hash))
	if err != nil {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(rec.Username)) == 1
	return userOK && subtle.ConstantTimeCompare(hash, rec.Hash) == 1
}

func (a *webAuth) username() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rec == nil {
		return ""
	}
	return a.rec.Username
}

// --- sessions: "<expiry unix>.<hmac>" signed with the sealed session key ---

func (a *webAuth) sign(exp string) string {
	a.mu.Lock()
	key := a.rec.SessionKey
	a.mu.Unlock()
	m := hmac.New(sha256.New, key)
	m.Write([]byte(exp))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *webAuth) issueSession(w http.ResponseWriter) {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: exp + "." + a.sign(exp), Path: "/", HttpOnly: true,
		// Lax, not Strict: an OAuth provider returns the operator here by top-level navigation
		// from its own domain, and Strict would withhold the session. Lax still refuses to send
		// the cookie on cross-site POSTs, which is where this dashboard's state changes happen.
		SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(sessionTTL),
	})
}

func (a *webAuth) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
}

func (a *webAuth) validSession(r *http.Request) bool {
	if !a.configured() {
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	if n, err := strconv.ParseInt(exp, 10, 64); err != nil || time.Now().Unix() > n {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(exp))) == 1
}

// require gates the dashboard: no .auth → /setup, no session → /login. htmx requests get an
// HX-Redirect so a partial swap never lands a login page inside a pane.
func (a *webAuth) require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		to := ""
		switch {
		case !a.configured():
			to = "/setup"
		case !a.validSession(r):
			to = "/login"
		}
		if to == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("HX-Request") != "" {
			w.Header().Set("HX-Redirect", to)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
	})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
