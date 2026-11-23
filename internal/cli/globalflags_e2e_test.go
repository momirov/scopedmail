package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/testserver"
)

// runRaw runs the binary with exactly args, so a test can repeat a global flag.
func (f *fixture) runRaw(env []string, args ...string) result {
	f.t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(append(os.Environ(), "SCOPEDMAIL_PASSWORD="+testserver.Password), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	exit := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			f.t.Fatal(err)
		}
		exit = ee.ExitCode()
	}
	return result{out.String(), errb.String(), exit}
}

// otherConfig writes a second config whose audit log sits beside it, so a run
// that used it leaves evidence.
func (f *fixture) otherConfig(name string) (config, auditLog string) {
	f.t.Helper()
	config = filepath.Join(f.dir, name+".toml")
	auditLog = filepath.Join(f.dir, name+".audit.jsonl")
	body := strings.Replace(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", readOnlyPolicy), f.audit, auditLog, 1)
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
	return config, auditLog
}

func TestRepeatedGlobalFlagIsAUsageError(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	other, otherAudit := f.otherConfig("other")
	for _, args := range [][]string{
		{"--config", f.config, "--config", other, "mailboxes"},
		{"--config", other, "--config", f.config, "mailboxes"},
		{"--config=" + f.config, "-config", other, "mailboxes"},
		{"--account", "work", "--account", "work", "--config", f.config, "mailboxes"},
		{"--config", f.config, "--account", "work", "--account", "other", "mailboxes"},
	} {
		r := f.runRaw(nil, args...)
		if r.exit != 2 || r.errCode(t) != "usage" || !strings.Contains(r.stderr, "more than once") {
			t.Errorf("%v: exit %d stderr %s", args, r.exit, r.stderr)
		}
	}
	for _, p := range []string{f.audit, otherAudit} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("a rejected invocation created %s", p)
		}
	}
	if len(f.srv.Commands()) != 0 {
		t.Error("a rejected invocation connected")
	}
}

func TestEmptyGlobalFlagIsAUsageError(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	other, _ := f.otherConfig("other")
	for _, args := range [][]string{
		{"--config", "", "mailboxes"},
		{"--config", f.config, "--account", "", "mailboxes"},
	} {
		r := f.runRaw([]string{"SCOPEDMAIL_CONFIG=" + other}, args...)
		if r.exit != 2 || r.errCode(t) != "usage" {
			t.Errorf("%v: exit %d stderr %s", args, r.exit, r.stderr)
		}
	}
}

func TestConfigFlagBeatsEnvironment(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	other, otherAudit := f.otherConfig("other")
	r := f.runRaw([]string{"SCOPEDMAIL_CONFIG=" + other, "XDG_CONFIG_HOME=" + f.dir}, "--config", f.config, "mailboxes")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	if _, err := os.Stat(f.audit); err != nil {
		t.Errorf("the --config file was not used: %v", err)
	}
	if _, err := os.Stat(otherAudit); err == nil {
		t.Error("SCOPEDMAIL_CONFIG overrode --config")
	}
	r = f.runRaw([]string{"SCOPEDMAIL_CONFIG=" + other}, "mailboxes")
	if r.exit != 0 {
		t.Fatalf("env only: exit %d: %s", r.exit, r.stderr)
	}
	if _, err := os.Stat(otherAudit); err != nil {
		t.Errorf("SCOPEDMAIL_CONFIG was ignored without --config: %v", err)
	}
}
