package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"delegent.dev/gateway/keyring"
	"delegent.dev/gateway/provision"
	"delegent.dev/gateway/rootkeys"
	"delegent.dev/gateway/store"
)

const (
	configFile    = "config.json"
	identityFile  = "identity.json"
	masterKeyFile = "master.key"
	// operatorExternalID keys the single local operator row — one operator per instance.
	operatorExternalID = "local-operator"
)

// config is the instance settings file — display-safe only, no secrets.
type config struct {
	ListenAddr string `json:"listen_addr"` // HTTP bind for serve (default 127.0.0.1:8090)
	AdminToken string `json:"admin_token"` // bearer the CLI presents to /admin on serve
	ConsoleURL string `json:"console_url,omitempty"`
}

// identity is the instance's stable ed25519 identity: the public half is the address a future
// peer gateway delegates slips to; the private half is sealed with the master key.
type identity struct {
	Pubkey    string `json:"pubkey"`     // hex
	SealedKey []byte `json:"sealed_key"` // ed25519 private key, sealed
	CreatedAt int64  `json:"created_at"` // unix ms
}

// homeFlag registers the shared --home flag on a subcommand's FlagSet.
func homeFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("DELEGENT_HOME")
	if def == "" {
		if h, err := os.UserHomeDir(); err == nil {
			def = filepath.Join(h, ".delegent")
		} else {
			def = ".delegent"
		}
	}
	return fs.String("home", def, "instance home directory")
}

// masterKey resolves the sealing key: DELEGENT_MASTER_KEY (base64, 32 bytes) wins, else
// <home>/master.key. There is deliberately NO dev-key fallback here — the local gateway holds
// real credentials from day one.
func masterKey(home string) ([]byte, error) {
	if raw := os.Getenv("DELEGENT_MASTER_KEY"); raw != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("DELEGENT_MASTER_KEY is not valid base64: %w", err)
		}
		return key, nil
	}
	raw, err := os.ReadFile(filepath.Join(home, masterKeyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("no master key: set DELEGENT_MASTER_KEY or run 'delegent-gateway init'")
		}
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", masterKeyFile, err)
	}
	return key, nil
}

// env is one opened instance: store, sealer, config, and the operator.
type env struct {
	home   string
	st     *store.JSONFileStore
	sealer keyring.Sealer
	cfg    config
	// operator is the single local user id; empty before init.
	operator string
}

// openEnv opens the instance at home. It fails with a run-init hint when the home dir was
// never initialized.
func openEnv(ctx context.Context, home string) (*env, error) {
	key, err := masterKey(home)
	if err != nil {
		return nil, err
	}
	sealer, err := keyring.NewAESSealer(key)
	if err != nil {
		return nil, err
	}
	st, err := store.NewJSONFileStore(home)
	if err != nil {
		return nil, err
	}
	e := &env{home: home, st: st, sealer: sealer}
	if err := e.loadConfig(); err != nil {
		return nil, err
	}
	if u, err := st.GetUserByExternal(ctx, operatorExternalID); err == nil {
		e.operator = u.ID
	}
	return e, nil
}

// requireOperator is openEnv + the guarantee init ran.
func requireOperator(ctx context.Context, home string) (*env, error) {
	e, err := openEnv(ctx, home)
	if err != nil {
		return nil, err
	}
	if e.operator == "" {
		return nil, errors.New("no operator provisioned — run 'delegent-gateway init' first")
	}
	return e, nil
}

func (e *env) loadConfig() error {
	raw, err := os.ReadFile(filepath.Join(e.home, configFile))
	if os.IsNotExist(err) {
		e.cfg = config{ListenAddr: "127.0.0.1:8090"}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &e.cfg); err != nil {
		return fmt.Errorf("parse %s: %w", configFile, err)
	}
	if e.cfg.ListenAddr == "" {
		e.cfg.ListenAddr = "127.0.0.1:8090"
	}
	return nil
}

func (e *env) saveConfig() error {
	data, err := json.MarshalIndent(e.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.home, configFile), append(data, '\n'), 0o600)
}

func nowMillis() int64 { return time.Now().UnixMilli() }

func randomToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS entropy source is gone; nothing sensible to do
	}
	return hex.EncodeToString(b)
}

// cmdInit provisions the instance: home dir, master key, config (with admin token), the
// operator user + sealed root signing key, and the instance identity keypair. Idempotent —
// re-running keeps every existing artifact.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	home := homeFlag(fs)
	listen := fs.String("listen", "", "HTTP listen address for serve (default 127.0.0.1:8090)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()

	if err := os.MkdirAll(*home, 0o700); err != nil {
		return err
	}

	// master key: keep an existing one (env or file); generate the file otherwise
	keyPath := filepath.Join(*home, masterKeyFile)
	if _, err := masterKey(*home); err != nil {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Printf("• master key generated → %s (keep it safe; secrets are unrecoverable without it)\n", keyPath)
	} else {
		fmt.Println("• master key present")
	}

	e, err := openEnv(ctx, *home)
	if err != nil {
		return err
	}
	if *listen != "" {
		e.cfg.ListenAddr = *listen
	}
	if e.cfg.AdminToken == "" {
		e.cfg.AdminToken = randomToken(24)
	}
	if err := e.saveConfig(); err != nil {
		return err
	}
	fmt.Printf("• config → %s (listen %s)\n", filepath.Join(*home, configFile), e.cfg.ListenAddr)

	// the single operator, with a sealed root signing key (signs slips and receipt chains)
	if e.operator == "" {
		keys := rootkeys.New(e.st, e.sealer)
		uid, err := provision.EnsureUser(ctx, e.st, keys, operatorExternalID, "", "operator")
		if err != nil {
			return err
		}
		e.operator = uid
		fmt.Printf("• operator provisioned (%s) with a sealed root signing key\n", uid)
	} else {
		fmt.Printf("• operator present (%s)\n", e.operator)
	}

	// instance identity: the stable address of this gateway for future cross-instance delegation
	idPath := filepath.Join(*home, identityFile)
	if _, err := os.Stat(idPath); os.IsNotExist(err) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		sealed, err := e.sealer.Seal(priv)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(identity{Pubkey: hex.EncodeToString(pub), SealedKey: sealed, CreatedAt: nowMillis()}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(idPath, append(data, '\n'), 0o600); err != nil {
			return err
		}
		fmt.Printf("• instance identity minted → %s\n", idPath)
	} else {
		fmt.Println("• instance identity present")
	}

	fmt.Printf(`
initialized %s

next:
  delegent-gateway target add --id github --endpoint https://api.example.com/mcp --credential <token>
  delegent-gateway key mint --name my-agent
  delegent-gateway serve            # or: delegent-gateway stdio --key <agent key>
`, *home)
	return nil
}
