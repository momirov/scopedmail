// Package config parses and validates the TOML config. It is the only place
// untrusted file text becomes typed values; everything downstream trusts them.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/momirov/labelgate/internal/fsperm"
	"github.com/momirov/labelgate/internal/policy"
)

type Auth string

const (
	AuthPassword Auth = "password"
	AuthOAuth2   Auth = "oauth2"
)

type Account struct {
	Name     string
	Host     string
	Port     int
	Username string
	// StartTLS upgrades a plain connection on port 143. Without it the
	// connection is implicit TLS. There is no plaintext mode.
	StartTLS bool
	// TLSCAFile, when set, replaces the system roots as the trust anchor, for
	// self-hosted servers with a private CA.
	TLSCAFile string
	Auth      Auth

	PasswordCmd    []string
	PasswordEnv    string
	OAuth2TokenCmd []string

	Policy policy.Policy
}

type Config struct {
	DefaultAccount string
	AuditLog       string
	Accounts       map[string]Account
}

type rawConfig struct {
	DefaultAccount string                `toml:"default_account"`
	AuditLog       string                `toml:"audit_log"`
	Accounts       map[string]rawAccount `toml:"accounts"`
}

type rawAccount struct {
	Host           string    `toml:"host"`
	Port           int       `toml:"port"`
	Username       string    `toml:"username"`
	StartTLS       bool      `toml:"starttls"`
	TLSCAFile      string    `toml:"tls_ca_file"`
	Auth           string    `toml:"auth"`
	PasswordCmd    []string  `toml:"password_cmd"`
	PasswordEnv    string    `toml:"password_env"`
	OAuth2TokenCmd []string  `toml:"oauth2_token_cmd"`
	Policy         rawPolicy `toml:"policy"`
}

type rawPolicy struct {
	Allow   []string `toml:"allow"`
	Deny    []string `toml:"deny"`
	Actions []string `toml:"actions"`
	Trash   string   `toml:"trash"`
}

// DefaultPath resolves the config location: flag, then $LABELGATE_CONFIG, then
// $XDG_CONFIG_HOME/labelgate/config.toml, then ~/.config/labelgate/config.toml.
func DefaultPath(flagValue string, getenv func(string) string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if p := getenv("LABELGATE_CONFIG"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "labelgate", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate config: %w", err)
	}
	return filepath.Join(home, ".config", "labelgate", "config.toml"), nil
}

// Load reads path, refusing a file that group or others can write.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config: %s is not a regular file", path)
	}
	if err := fsperm.RejectWritableByOthers(path, info); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var raw rawConfig
	md, err := toml.NewDecoder(f).Decode(&raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := rejectUndecoded(md.Undecoded()); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg, err := build(raw, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

func rejectUndecoded(keys []toml.Key) error {
	if len(keys) == 0 {
		return nil
	}
	for _, k := range keys {
		if k[len(k)-1] == "password" {
			return fmt.Errorf("%s: inline passwords are not supported; use password_cmd or password_env", k)
		}
	}
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = k.String()
	}
	sort.Strings(names)
	return fmt.Errorf("unknown key %s", strings.Join(names, ", "))
}

func build(raw rawConfig, dir string) (*Config, error) {
	cfg := &Config{DefaultAccount: raw.DefaultAccount, Accounts: map[string]Account{}}
	var err error
	if raw.AuditLog == "" {
		return nil, errors.New("audit_log is required")
	}
	if cfg.AuditLog, err = expandHome(raw.AuditLog); err != nil {
		return nil, fmt.Errorf("audit_log: %w", err)
	}
	if !filepath.IsAbs(cfg.AuditLog) {
		return nil, errors.New("audit_log must be an absolute path or start with ~/")
	}
	if len(raw.Accounts) == 0 {
		return nil, errors.New("no accounts configured")
	}
	for name, ra := range raw.Accounts {
		acct, err := buildAccount(name, ra, dir)
		if err != nil {
			return nil, fmt.Errorf("accounts.%s: %w", name, err)
		}
		cfg.Accounts[name] = acct
	}
	if cfg.DefaultAccount != "" {
		if _, ok := cfg.Accounts[cfg.DefaultAccount]; !ok {
			return nil, fmt.Errorf("default_account %q is not defined", cfg.DefaultAccount)
		}
	}
	return cfg, nil
}

func buildAccount(name string, ra rawAccount, dir string) (Account, error) {
	a := Account{
		Name:           name,
		Host:           ra.Host,
		Port:           ra.Port,
		Username:       ra.Username,
		StartTLS:       ra.StartTLS,
		Auth:           Auth(ra.Auth),
		PasswordCmd:    ra.PasswordCmd,
		PasswordEnv:    ra.PasswordEnv,
		OAuth2TokenCmd: ra.OAuth2TokenCmd,
	}
	if a.Host == "" || strings.ContainsAny(a.Host, " \t/") {
		return a, errors.New("host is required and must be a bare hostname")
	}
	if a.Username == "" {
		return a, errors.New("username is required")
	}
	if a.Port == 0 {
		a.Port = 993
		if a.StartTLS {
			a.Port = 143
		}
	}
	if a.Port < 1 || a.Port > 65535 {
		return a, fmt.Errorf("port %d out of range", a.Port)
	}
	if ra.TLSCAFile != "" {
		p, err := expandHome(ra.TLSCAFile)
		if err != nil {
			return a, fmt.Errorf("tls_ca_file: %w", err)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		a.TLSCAFile = p
	}
	switch a.Auth {
	case AuthPassword:
		if (len(a.PasswordCmd) == 0) == (a.PasswordEnv == "") {
			return a, errors.New(`auth "password" needs exactly one of password_cmd or password_env`)
		}
		if len(a.OAuth2TokenCmd) > 0 {
			return a, errors.New(`oauth2_token_cmd only applies to auth "oauth2"`)
		}
		if len(a.PasswordCmd) > 0 && a.PasswordCmd[0] == "" {
			return a, errors.New("password_cmd has an empty program name")
		}
	case AuthOAuth2:
		if len(a.OAuth2TokenCmd) == 0 || a.OAuth2TokenCmd[0] == "" {
			return a, errors.New(`auth "oauth2" needs oauth2_token_cmd`)
		}
		if len(a.PasswordCmd) > 0 || a.PasswordEnv != "" {
			return a, errors.New(`password_cmd and password_env only apply to auth "password"`)
		}
	case "":
		return a, errors.New(`auth is required ("password" or "oauth2")`)
	default:
		return a, fmt.Errorf("unknown auth %q", a.Auth)
	}
	pol, err := policy.New(policy.Spec{
		Allow:   ra.Policy.Allow,
		Deny:    ra.Policy.Deny,
		Actions: ra.Policy.Actions,
		Trash:   ra.Policy.Trash,
	})
	if err != nil {
		return a, fmt.Errorf("policy: %w", err)
	}
	a.Policy = pol
	return a, nil
}

// Account picks the named account, else default_account, else the only one.
func (c *Config) Account(name string) (Account, error) {
	if name == "" {
		name = c.DefaultAccount
	}
	if name == "" && len(c.Accounts) == 1 {
		for n := range c.Accounts {
			name = n
		}
	}
	if name == "" {
		return Account{}, errors.New("no account selected: pass --account or set default_account")
	}
	a, ok := c.Accounts[name]
	if !ok {
		return Account{}, fmt.Errorf("unknown account %q", name)
	}
	return a, nil
}

func expandHome(p string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}
