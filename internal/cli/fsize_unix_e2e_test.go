//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/momirov/scopedmail/internal/testserver"
)

const fsizeEnv = "SCOPEDMAIL_TEST_FSIZE"

// init turns the test binary into an rlimit wrapper, the way `ulimit -f` in a
// shell would: it sets RLIMIT_FSIZE to the "soft,hard" bytes in fsizeEnv and
// execs its arguments. It runs before TestMain, so the child never builds.
func init() {
	v := os.Getenv(fsizeEnv)
	if v == "" {
		return
	}
	soft, hard, _ := strings.Cut(v, ",")
	var lim unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_FSIZE, &lim)
	cur, err1 := strconv.ParseUint(soft, 10, 64)
	max, err2 := strconv.ParseUint(hard, 10, 64)
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "bad", fsizeEnv, v)
		os.Exit(99)
	}
	lim.Cur, lim.Max = cur, max
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &lim); err != nil {
		fmt.Fprintln(os.Stderr, "setrlimit:", err)
		os.Exit(99)
	}
	os.Unsetenv(fsizeEnv)
	err := unix.Exec(os.Args[1], os.Args[1:], os.Environ())
	fmt.Fprintln(os.Stderr, "exec:", err)
	os.Exit(99)
}

// runLimited runs the binary under a file size limit, as an agent that sets
// `ulimit -f` before calling the sudo wrapper would.
func (f *fixture) runLimited(soft, hard uint64, args ...string) result {
	f.t.Helper()
	self, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	cmd := exec.Command(self, append([]string{binary, "--config", f.config}, args...)...)
	cmd.Env = append(os.Environ(), "SCOPEDMAIL_PASSWORD="+testserver.Password, fmt.Sprintf("%s=%d,%d", fsizeEnv, soft, hard))
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
	if exit == 99 {
		f.t.Fatalf("rlimit helper failed: %s", errb.String())
	}
	return result{out.String(), errb.String(), exit}
}

func (f *fixture) logSize() uint64 {
	f.t.Helper()
	info, err := os.Stat(f.audit)
	if err != nil {
		f.t.Fatal(err)
	}
	return uint64(info.Size())
}

func TestSendUnderAFileSizeLimitIsRefusedAndNothingIsDelivered(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	if r := f.run("read", "-m", "Agent", "1"); r.exit != 0 {
		t.Fatalf("read: %+v", r)
	}
	before := len(f.records())
	size := f.logSize()
	r := f.runLimited(size, size, "send", "--to", "bob@example.com", "--subject", "fsize", "--body", "unlogged")
	if r.exit != 1 || r.errCode(t) != "audit" {
		t.Errorf("exit = %d, stderr = %s; want a refused audit log", r.exit, r.stderr)
	}
	if n, c := len(f.smtp.Deliveries()), f.smtp.Connections(); n != 0 || c != 0 {
		t.Errorf("deliveries = %d, smtp connections = %d; an unrecorded send went out", n, c)
	}
	if after := len(f.records()); after != before {
		t.Errorf("records went from %d to %d", before, after)
	}
}

func TestSoftFileSizeLimitIsRaisedToTheHardLimit(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	if r := f.run("read", "-m", "Agent", "1"); r.exit != 0 {
		t.Fatalf("read: %+v", r)
	}
	size := f.logSize()
	r := f.runLimited(size, unix.RLIM_INFINITY, "send", "--to", "bob@example.com", "--subject", "fsize", "--body", "logged")
	if r.exit != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.exit, r.stderr)
	}
	if n := len(f.smtp.Deliveries()); n != 1 {
		t.Errorf("deliveries = %d, want 1", n)
	}
	recs := f.records()
	if last := recs[len(recs)-1]; last.Action != "send" || last.Outcome != "ok" || last.IntentSeq == 0 {
		t.Errorf("last record = %+v, want a send outcome linked to its intent", last)
	}
}
