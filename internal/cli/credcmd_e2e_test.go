package cli_test

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/testserver"
)

// hostileCat puts a cat earlier on PATH that records that it ran, as an agent
// whose PATH survives sudo could.
func hostileCat(t *testing.T, dir string) (pathDir, ranFile string) {
	t.Helper()
	pathDir, ranFile = filepath.Join(dir, "evil"), filepath.Join(dir, "evil-ran")
	if err := os.Mkdir(pathDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\ntouch %q\nexec /bin/cat \"$@\"\n", ranFile)
	if err := os.WriteFile(filepath.Join(pathDir, "cat"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return pathDir, ranFile
}

func TestCredentialCommandIgnoresTheCallersPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses unix shell scripts")
	}
	f := newFixture(t, readOnlyPolicy)
	pw := filepath.Join(f.dir, "pw")
	if err := os.WriteFile(pw, []byte(testserver.Password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evil, ran := hostileCat(t, f.dir)
	hijacked := []string{"PATH=" + evil + string(os.PathListSeparator) + os.Getenv("PATH")}

	f.writeConfig(f.accountBlock(fmt.Sprintf("tls_ca_file = \"ca.pem\"\npassword_cmd = [\"cat\", %q]", pw), readOnlyPolicy))
	if r := f.runRaw(hijacked, "--config", f.config, "mailboxes"); r.exit != 1 || r.errCode(t) != "config" || !strings.Contains(r.stderr, "absolute path") {
		t.Errorf("bare password_cmd: exit %d stderr %s", r.exit, r.stderr)
	}

	f.writeConfig(f.accountBlock(fmt.Sprintf("tls_ca_file = \"ca.pem\"\npassword_cmd = [\"/bin/sh\", \"-c\", \"cat %s\"]", pw), readOnlyPolicy))
	if r := f.runRaw(hijacked, "--config", f.config, "mailboxes"); r.exit != 0 {
		t.Errorf("absolute password_cmd: exit %d stderr %s", r.exit, r.stderr)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Error("the cat on the caller's PATH ran")
	}
}

func TestCredentialCommandGetsAFixedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses unix shell scripts")
	}
	f := newFixture(t, readOnlyPolicy)
	envOut := filepath.Join(f.dir, "env")
	script := filepath.Join(f.dir, "pw.sh")
	body := fmt.Sprintf("#!/bin/sh\nenv > %q\nprintf '%%s\\n' '%s'\n", envOut, testserver.Password)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	f.writeConfig(f.accountBlock(fmt.Sprintf("tls_ca_file = \"ca.pem\"\npassword_cmd = [%q]", script), readOnlyPolicy))
	if r := f.runRaw([]string{"HOME=/agent/home", "LD_PRELOAD=/agent/lib.so", "AGENT_MARKER=1"}, "--config", f.config, "mailboxes"); r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	got := readFile(t, envOut)
	for _, want := range []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin\n", "HOME=" + u.HomeDir + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("environment lacks %q:\n%s", want, got)
		}
	}
	for _, leak := range []string{"/agent/home", "LD_PRELOAD", "AGENT_MARKER", "SCOPEDMAIL_PASSWORD"} {
		if strings.Contains(got, leak) {
			t.Errorf("environment holds %q:\n%s", leak, got)
		}
	}
}
