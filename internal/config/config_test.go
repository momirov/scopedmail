package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConfig = `
default_account = "work"
audit_log = "/var/lib/labelgate/audit.jsonl"

[accounts.work]
host = "imap.gmail.com"
username = "me@example.com"
auth = "password"
password_env = "LABELGATE_PASSWORD"

[accounts.work.policy]
allow = ["Agent", "Receipts/*"]
deny = ["Receipts/Tax"]
actions = ["mailboxes", "search", "read", "flag"]
trash = "[Gmail]/Trash"
`

func writeConfig(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGoodConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, goodConfig, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	a, err := cfg.Account("")
	if err != nil {
		t.Fatal(err)
	}
	if a.Port != 993 || a.StartTLS {
		t.Errorf("defaults: port=%d starttls=%v, want 993 implicit TLS", a.Port, a.StartTLS)
	}
	if !a.Policy.MailboxAllowed("Receipts/Food") || a.Policy.MailboxAllowed("Receipts/Tax") || a.Policy.MailboxAllowed("INBOX") {
		t.Error("policy was not built from the [policy] table")
	}
	if cfg.AuditLog != "/var/lib/labelgate/audit.jsonl" {
		t.Errorf("audit_log = %q", cfg.AuditLog)
	}
}

func TestStartTLSDefaultsToPort143(t *testing.T) {
	body := strings.Replace(goodConfig, `auth = "password"`, "auth = \"password\"\nstarttls = true", 1)
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cfg.Account(""); a.Port != 143 || !a.StartTLS {
		t.Errorf("port=%d starttls=%v", a.Port, a.StartTLS)
	}
}

func TestLoadRefusesGroupOrWorldWritable(t *testing.T) {
	for _, mode := range []os.FileMode{0o660, 0o666, 0o620, 0o602} {
		if _, err := Load(writeConfig(t, goodConfig, mode)); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("mode %04o: err = %v, want writable refusal", mode, err)
		}
	}
}

func TestLoadAcceptsReadableByOthers(t *testing.T) {
	if _, err := Load(writeConfig(t, goodConfig, 0o644)); err != nil {
		t.Errorf("0644 should load (only writability is refused): %v", err)
	}
}

func TestInlinePasswordIsAParseError(t *testing.T) {
	body := strings.Replace(goodConfig, `password_env = "LABELGATE_PASSWORD"`, `password = "hunter2"`, 1)
	_, err := Load(writeConfig(t, body, 0o600))
	if err == nil || !strings.Contains(err.Error(), "inline passwords") {
		t.Fatalf("err = %v, want inline-password refusal", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("error message leaks the password value")
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	for name, extra := range map[string]string{
		"skip verify": "insecure_skip_verify = true",
		"plaintext":   "plaintext = true",
		"typo":        "starttls_enabled = true",
		"policy typo": "[accounts.work.policy.extra]\nx = 1",
		"top level":   "",
	} {
		body := goodConfig
		if name == "top level" {
			body = "bogus = 1\n" + goodConfig
		} else {
			body = strings.Replace(goodConfig, `auth = "password"`, "auth = \"password\"\n"+extra, 1)
		}
		if name == "policy typo" {
			body = goodConfig + "\n" + extra + "\n"
		}
		if _, err := Load(writeConfig(t, body, 0o600)); err == nil || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: err = %v, want unknown key", name, err)
		}
	}
}

func TestPolicyErrorsSurfaceAtLoad(t *testing.T) {
	for name, repl := range map[string]string{
		"bare star":   `allow = ["*"]`,
		"unknown act": `allow = ["A"]` + "\n" + `actions = ["nuke"]`,
		"gmail wild":  `allow = ["[Gmail]/*"]`,
	} {
		body := strings.Replace(goodConfig, "allow = [\"Agent\", \"Receipts/*\"]\ndeny = [\"Receipts/Tax\"]\nactions = [\"mailboxes\", \"search\", \"read\", \"flag\"]", repl, 1)
		if _, err := Load(writeConfig(t, body, 0o600)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
}

func TestCredentialRules(t *testing.T) {
	tests := map[string]string{
		"missing auth":     strings.Replace(goodConfig, `auth = "password"`, "", 1),
		"no credential":    strings.Replace(goodConfig, `password_env = "LABELGATE_PASSWORD"`, "", 1),
		"both credentials": strings.Replace(goodConfig, `password_env = "LABELGATE_PASSWORD"`, "password_env = \"X\"\npassword_cmd = [\"echo\"]", 1),
		"unknown auth":     strings.Replace(goodConfig, `"password"`, `"plain"`, 1),
		"oauth no cmd":     strings.Replace(goodConfig, `auth = "password"`, `auth = "oauth2"`, 1),
		"missing host":     strings.Replace(goodConfig, `host = "imap.gmail.com"`, "", 1),
		"bad port":         strings.Replace(goodConfig, `auth = "password"`, "auth = \"password\"\nport = 99999", 1),
		"missing audit":    strings.Replace(goodConfig, `audit_log = "/var/lib/labelgate/audit.jsonl"`, "", 1),
		"relative audit":   strings.Replace(goodConfig, `/var/lib/labelgate/audit.jsonl`, "audit.jsonl", 1),
		"bad default":      strings.Replace(goodConfig, `default_account = "work"`, `default_account = "nope"`, 1),
	}
	for name, body := range tests {
		if _, err := Load(writeConfig(t, body, 0o600)); err == nil {
			t.Errorf("%s: Load succeeded, want error", name)
		}
	}
}

func TestOAuth2Account(t *testing.T) {
	body := strings.Replace(goodConfig, `auth = "password"
password_env = "LABELGATE_PASSWORD"`, `auth = "oauth2"
oauth2_token_cmd = ["gcloud", "auth", "print-access-token"]`, 1)
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cfg.Account("work"); a.Auth != AuthOAuth2 || len(a.OAuth2TokenCmd) != 3 {
		t.Errorf("account = %+v", a)
	}
}

func TestTLSCAFileResolvesRelativeToConfig(t *testing.T) {
	body := strings.Replace(goodConfig, `auth = "password"`, "auth = \"password\"\ntls_ca_file = \"ca.pem\"", 1)
	path := writeConfig(t, body, 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cfg.Account("")
	if want := filepath.Join(filepath.Dir(path), "ca.pem"); a.TLSCAFile != want {
		t.Errorf("TLSCAFile = %q, want %q", a.TLSCAFile, want)
	}
}

func TestAccountSelection(t *testing.T) {
	two := goodConfig + "\n[accounts.other]\nhost = \"h\"\nusername = \"u\"\nauth = \"password\"\npassword_env = \"P\"\n"
	cfg, err := Load(writeConfig(t, two, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, err := cfg.Account("other"); err != nil || a.Name != "other" {
		t.Errorf("explicit: %v %v", a.Name, err)
	}
	if a, err := cfg.Account(""); err != nil || a.Name != "work" {
		t.Errorf("default: %v %v", a.Name, err)
	}
	if _, err := cfg.Account("missing"); err == nil {
		t.Error("unknown account accepted")
	}
	noDefault := strings.Replace(two, `default_account = "work"`, "", 1)
	cfg, err = Load(writeConfig(t, noDefault, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Account(""); err == nil {
		t.Error("ambiguous account accepted")
	}
}

func TestDefaultPathPrecedence(t *testing.T) {
	env := map[string]string{"LABELGATE_CONFIG": "/e/c.toml", "XDG_CONFIG_HOME": "/xdg"}
	get := func(k string) string { return env[k] }
	if p, _ := DefaultPath("/flag.toml", get); p != "/flag.toml" {
		t.Errorf("flag: %q", p)
	}
	if p, _ := DefaultPath("", get); p != "/e/c.toml" {
		t.Errorf("env: %q", p)
	}
	delete(env, "LABELGATE_CONFIG")
	if p, _ := DefaultPath("", get); p != filepath.Join("/xdg", "labelgate", "config.toml") {
		t.Errorf("xdg: %q", p)
	}
	delete(env, "XDG_CONFIG_HOME")
	home, _ := os.UserHomeDir()
	if p, _ := DefaultPath("", get); p != filepath.Join(home, ".config", "labelgate", "config.toml") {
		t.Errorf("home: %q", p)
	}
}

func TestHomeExpansionInAuditLog(t *testing.T) {
	body := strings.Replace(goodConfig, `/var/lib/labelgate/audit.jsonl`, "~/.local/state/labelgate/audit.jsonl", 1)
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, ".local/state/labelgate/audit.jsonl"); cfg.AuditLog != want {
		t.Errorf("audit_log = %q, want %q", cfg.AuditLog, want)
	}
}
