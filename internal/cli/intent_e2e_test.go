package cli_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/testserver"
)

// stallingListener accepts connections and never answers, so a send through
// it stays between its intent and its outcome until the process dies.
func stallingListener(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().(*net.TCPAddr)
}

func TestKilledSendLeavesAnUnfinishedIntent(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	addr := stallingListener(t)
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", sendPolicy+fmt.Sprintf(`
[accounts.work.smtp]
host = %q
port = %d
`, addr.IP.String(), addr.Port)))

	cmd := exec.Command(binary, "--config", f.config, "send", "--to", "bob@example.com", "--subject", "s", "--body", "b")
	cmd.Env = append(os.Environ(), "SCOPEDMAIL_PASSWORD="+testserver.Password)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(readFile(t, f.audit), `"outcome":"started"`) {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("no intent was recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Kill()
	cmd.Wait()

	r := f.run("audit", "verify")
	var v struct {
		OK         bool     `json:"ok"`
		Unfinished []uint64 `json:"unfinished"`
	}
	r.json(t, &v)
	if !v.OK || !slices.Equal(v.Unfinished, []uint64{1}) {
		t.Errorf("verify = %s, want ok with unfinished [1]", r.stdout)
	}
	var tail []audit.Record
	f.run("audit", "tail").json(t, &tail)
	if len(tail) != 1 || tail[0].Outcome != audit.OutcomeStarted || tail[0].Action != "send" || tail[0].Args["to"] != "bob@example.com" {
		t.Errorf("tail = %+v, want the started send", tail)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}
