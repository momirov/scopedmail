package cli_test

import (
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/audit"
)

// twoAccounts adds an account "boss" that may read Private and shares the
// audit log with "work".
func twoAccounts(f *fixture) {
	f.t.Helper()
	work := f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", readOnlyPolicy)
	i := strings.Index(work, "[accounts.work]")
	boss := strings.NewReplacer("accounts.work", "accounts.boss", readOnlyPolicy, `allow = ["Private"]`).Replace(work[i:])
	f.writeConfig(work + "\n" + boss)
}

func TestAuditTailShowsOnlyTheSelectedAccount(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	twoAccounts(f)
	if r := f.run("--account", "boss", "read", "-m", "Private", "1"); r.exit != 0 {
		t.Fatalf("boss read: %d %s", r.exit, r.stderr)
	}
	if r := f.run("mailboxes"); r.exit != 0 {
		t.Fatalf("work mailboxes: %d %s", r.exit, r.stderr)
	}
	var tail []audit.Record
	f.run("audit", "tail").json(t, &tail)
	if len(tail) != 1 || tail[0].Account != "work" || tail[0].Action != "mailboxes" {
		t.Errorf("work's tail = %+v, want only work's mailboxes record", tail)
	}
	var verify struct{ Records uint64 }
	f.run("audit", "verify").json(t, &verify)
	if verify.Records != 2 {
		t.Errorf("verify counted %d records, want both accounts' 2", verify.Records)
	}
}
