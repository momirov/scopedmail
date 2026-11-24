package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/policy"
)

const goodConfig = `
default_account = "work"
audit_log = "/var/lib/scopedmail/audit.jsonl"

[accounts.work]
host = "imap.gmail.com"
username = "me@example.com"
auth = "password"
password_env = "SCOPEDMAIL_PASSWORD"

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
	if cfg.AuditLog != "/var/lib/scopedmail/audit.jsonl" {
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
	body := strings.Replace(goodConfig, `password_env = "SCOPEDMAIL_PASSWORD"`, `password = "hunter2"`, 1)
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
		"no credential":    strings.Replace(goodConfig, `password_env = "SCOPEDMAIL_PASSWORD"`, "", 1),
		"both credentials": strings.Replace(goodConfig, `password_env = "SCOPEDMAIL_PASSWORD"`, "password_env = \"X\"\npassword_cmd = [\"echo\"]", 1),
		"unknown auth":     strings.Replace(goodConfig, `"password"`, `"plain"`, 1),
		"oauth no cmd":     strings.Replace(goodConfig, `auth = "password"`, `auth = "oauth2"`, 1),
		"missing host":     strings.Replace(goodConfig, `host = "imap.gmail.com"`, "", 1),
		"bad port":         strings.Replace(goodConfig, `auth = "password"`, "auth = \"password\"\nport = 99999", 1),
		"missing audit":    strings.Replace(goodConfig, `audit_log = "/var/lib/scopedmail/audit.jsonl"`, "", 1),
		"relative audit":   strings.Replace(goodConfig, `/var/lib/scopedmail/audit.jsonl`, "audit.jsonl", 1),
		"bad default":      strings.Replace(goodConfig, `default_account = "work"`, `default_account = "nope"`, 1),
	}
	for name, body := range tests {
		if _, err := Load(writeConfig(t, body, 0o600)); err == nil {
			t.Errorf("%s: Load succeeded, want error", name)
		}
	}
}

func TestCredentialCommandsNeedAnAbsoluteProgram(t *testing.T) {
	password := `auth = "password"
password_env = "SCOPEDMAIL_PASSWORD"`
	for name, repl := range map[string]string{
		"password_cmd bare name":     "auth = \"password\"\npassword_cmd = [\"cat\", \"/run/secret\"]",
		"password_cmd relative path": "auth = \"password\"\npassword_cmd = [\"bin/cat\", \"/run/secret\"]",
		"password_cmd empty":         "auth = \"password\"\npassword_cmd = [\"\"]",
		"oauth2_token_cmd bare name": "auth = \"oauth2\"\noauth2_token_cmd = [\"oama\", \"access\", \"me@example.com\"]",
	} {
		_, err := Load(writeConfig(t, strings.Replace(goodConfig, password, repl, 1), 0o600))
		if err == nil || !strings.Contains(err.Error(), "_cmd") {
			t.Errorf("%s: Load = %v, want an error naming the key", name, err)
		}
	}
	ok := strings.Replace(goodConfig, password, "auth = \"password\"\npassword_cmd = [\"/bin/cat\", \"/run/secret\"]", 1)
	if _, err := Load(writeConfig(t, ok, 0o600)); err != nil {
		t.Errorf("absolute password_cmd: %v", err)
	}
}

func TestOAuth2Account(t *testing.T) {
	body := strings.Replace(goodConfig, `auth = "password"
password_env = "SCOPEDMAIL_PASSWORD"`, `auth = "oauth2"
oauth2_token_cmd = ["/usr/bin/gcloud", "auth", "print-access-token"]`, 1)
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
	env := map[string]string{"SCOPEDMAIL_CONFIG": "/e/c.toml", "XDG_CONFIG_HOME": "/xdg"}
	get := func(k string) string { return env[k] }
	if p, _ := DefaultPath("/flag.toml", get); p != "/flag.toml" {
		t.Errorf("flag: %q", p)
	}
	if p, _ := DefaultPath("", get); p != "/e/c.toml" {
		t.Errorf("env: %q", p)
	}
	delete(env, "SCOPEDMAIL_CONFIG")
	if p, _ := DefaultPath("", get); p != filepath.Join("/xdg", "scopedmail", "config.toml") {
		t.Errorf("xdg: %q", p)
	}
	delete(env, "XDG_CONFIG_HOME")
	home, _ := os.UserHomeDir()
	if p, _ := DefaultPath("", get); p != filepath.Join(home, ".config", "scopedmail", "config.toml") {
		t.Errorf("home: %q", p)
	}
}

func TestHomeExpansionInAuditLog(t *testing.T) {
	body := strings.Replace(goodConfig, `/var/lib/scopedmail/audit.jsonl`, "~/.local/state/scopedmail/audit.jsonl", 1)
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if want := filepath.Join(home, ".local/state/scopedmail/audit.jsonl"); cfg.AuditLog != want {
		t.Errorf("audit_log = %q, want %q", cfg.AuditLog, want)
	}
}

const sendPolicyBody = `allow = ["Agent"]
actions = ["read", "send"]
send_to = ["alice@example.com", "@example.org"]
`

func withPolicy(body string) string {
	return strings.Replace(goodConfig, "allow = [\"Agent\", \"Receipts/*\"]\ndeny = [\"Receipts/Tax\"]\nactions = [\"mailboxes\", \"search\", \"read\", \"flag\"]", body, 1)
}

func TestSendDefaultsForGmail(t *testing.T) {
	cfg, err := Load(writeConfig(t, withPolicy(sendPolicyBody), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cfg.Account("")
	if a.SMTP != (SMTP{Host: "smtp.gmail.com", Port: 465}) {
		t.Errorf("SMTP = %+v, want smtp.gmail.com:465 implicit TLS", a.SMTP)
	}
	if d := a.Policy.CheckSend([]string{"ALICE@example.com", "x@example.org"}); !d.Allowed {
		t.Errorf("send_to was not parsed into the policy: %+v", d)
	}
	if d := a.Policy.CheckSend([]string{"x@example.com"}); d.Allowed {
		t.Error("x@example.com must not match alice@example.com")
	}
}

func TestSendDisabledByDefaultAndLeavesSMTPUnset(t *testing.T) {
	cfg, err := Load(writeConfig(t, goodConfig, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cfg.Account("")
	if a.Policy.ActionEnabled(policy.Send) || a.SMTP != (SMTP{}) {
		t.Errorf("send=%v smtp=%+v, want off and zero", a.Policy.ActionEnabled(policy.Send), a.SMTP)
	}
	noActions := withPolicy(`allow = ["Agent"]`)
	cfg, err = Load(writeConfig(t, noActions, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cfg.Account(""); a.Policy.ActionEnabled(policy.Send) {
		t.Error("send is in the default action set")
	}
}

func TestSendWithEmptySendToFailsLoad(t *testing.T) {
	for name, body := range map[string]string{
		"absent": "allow = [\"Agent\"]\nactions = [\"send\"]\n",
		"empty":  "allow = [\"Agent\"]\nactions = [\"send\"]\nsend_to = []\n",
	} {
		_, err := Load(writeConfig(t, withPolicy(body), 0o600))
		if err == nil || !strings.Contains(err.Error(), "send_to is empty") {
			t.Errorf("%s: err = %v, want send_to is empty", name, err)
		}
	}
}

func TestMalformedSendToFailsLoad(t *testing.T) {
	for _, bad := range []string{`"example.com"`, `"@com"`, `"*@example.com"`, `"Alice <a@example.com>"`} {
		body := withPolicy("allow = [\"Agent\"]\nactions = [\"send\"]\nsend_to = [" + bad + "]\n")
		if _, err := Load(writeConfig(t, body, 0o600)); err == nil || !strings.Contains(err.Error(), "send_to") {
			t.Errorf("%s: err = %v, want send_to error", bad, err)
		}
	}
}

func TestSMTPRequiredOutsideGmail(t *testing.T) {
	other := strings.Replace(withPolicy(sendPolicyBody), "imap.gmail.com", "imap.example.org", 1)
	if _, err := Load(writeConfig(t, other, 0o600)); err == nil || !strings.Contains(err.Error(), "smtp") {
		t.Errorf("err = %v, want an smtp requirement", err)
	}
	with := other + "\n[accounts.work.smtp]\nhost = \"smtp.example.org\"\nstarttls = true\n"
	cfg, err := Load(writeConfig(t, with, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cfg.Account(""); a.SMTP != (SMTP{Host: "smtp.example.org", Port: 587, StartTLS: true}) {
		t.Errorf("SMTP = %+v", a.SMTP)
	}
}

func TestSMTPTableValidation(t *testing.T) {
	base := withPolicy(sendPolicyBody)
	for name, tbl := range map[string]string{
		"bad port":     "host = \"smtp.example.org\"\nport = 70000",
		"bad host":     "host = \"smtp example.org\"",
		"unknown key":  "host = \"smtp.example.org\"\ninsecure = true",
		"port no host": "port = 25\nbogus = 1",
	} {
		if _, err := Load(writeConfig(t, base+"\n[accounts.work.smtp]\n"+tbl+"\n", 0o600)); err == nil {
			t.Errorf("%s: Load succeeded", name)
		}
	}
	cfg, err := Load(writeConfig(t, base+"\n[accounts.work.smtp]\nport = 2465\n", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := cfg.Account(""); a.SMTP != (SMTP{Host: "smtp.gmail.com", Port: 2465}) {
		t.Errorf("SMTP = %+v", a.SMTP)
	}
}

func TestMaxRecipientsFromConfig(t *testing.T) {
	body := withPolicy(sendPolicyBody + "max_recipients = 1\n")
	cfg, err := Load(writeConfig(t, body, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := cfg.Account("")
	if d := a.Policy.CheckSend([]string{"alice@example.com", "x@example.org"}); d.Allowed {
		t.Errorf("two recipients under max_recipients=1: %+v", d)
	}
}

func TestSendNeedsEmailUsername(t *testing.T) {
	body := strings.Replace(withPolicy(sendPolicyBody), `me@example.com`, "me", 1)
	if _, err := Load(writeConfig(t, body, 0o600)); err == nil || !strings.Contains(err.Error(), "From") {
		t.Errorf("err = %v, want a From-address requirement", err)
	}
}

func TestFilesDirMayNotHoldTheCAFile(t *testing.T) {
	dir := t.TempDir()
	files := filepath.Join(dir, "files")
	for name, ca := range map[string]string{
		"absolute": filepath.Join(files, "ca.pem"),
		"relative": "files/ca.pem",
	} {
		body := strings.Replace(goodConfig, `password_env = "SCOPEDMAIL_PASSWORD"`, fmt.Sprintf("password_env = \"SCOPEDMAIL_PASSWORD\"\nfiles_dir = %q\ntls_ca_file = %q", files, ca), 1)
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ca.pem") {
			t.Errorf("%s tls_ca_file inside files_dir: Load = %v", name, err)
		}
	}
	body := strings.Replace(goodConfig, `password_env = "SCOPEDMAIL_PASSWORD"`, fmt.Sprintf("password_env = \"SCOPEDMAIL_PASSWORD\"\nfiles_dir = %q\ntls_ca_file = %q", files, filepath.Join(dir, "ca.pem")), 1)
	if _, err := Load(writeConfig(t, body, 0o600)); err != nil {
		t.Errorf("tls_ca_file beside files_dir: %v", err)
	}
}

func TestAllowKeywordsReachesThePolicy(t *testing.T) {
	on := strings.Replace(goodConfig, `trash = "[Gmail]/Trash"`, "trash = \"[Gmail]/Trash\"\nallow_keywords = true", 1)
	for body, want := range map[string]bool{goodConfig: false, on: true} {
		cfg, err := Load(writeConfig(t, body, 0o600))
		if err != nil {
			t.Fatal(err)
		}
		a, _ := cfg.Account("work")
		if got := a.Policy.CheckKeywords([]string{"Project"}).Allowed; got != want {
			t.Errorf("allow_keywords %v: keyword allowed = %v", want, got)
		}
	}
}
