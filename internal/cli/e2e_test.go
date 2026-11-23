package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/testserver"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "scopedmail-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	name := "scopedmail"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary = filepath.Join(dir, name)
	build := exec.Command("go", "build", "-o", binary, "../../cmd/scopedmail")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type fixture struct {
	t      *testing.T
	srv    *testserver.Server
	dir    string
	config string
	audit  string
}

const readOnlyPolicy = `allow = ["Agent", "Agent/*", "INBOX"]`

const allActions = `
actions = ["mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox"]`

func newFixture(t *testing.T, policyBody string) *fixture {
	t.Helper()
	srv, err := testserver.Start(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	f := &fixture{t: t, srv: srv, dir: t.TempDir()}
	f.audit = filepath.Join(f.dir, "audit.jsonl")
	if err := os.WriteFile(filepath.Join(f.dir, "ca.pem"), srv.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", policyBody))
	return f
}

func (f *fixture) accountBlock(extra, policyBody string) string {
	return fmt.Sprintf(`
audit_log = %q
default_account = "work"

[accounts.work]
host = %q
port = %d
username = %q
auth = "password"
%s

[accounts.work.policy]
%s
`, f.audit, f.srv.Host, f.srv.Port, testserver.Username, extra, policyBody)
}

func (f *fixture) writeConfig(body string) {
	f.t.Helper()
	f.config = filepath.Join(f.dir, "config.toml")
	if err := os.WriteFile(f.config, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.config, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

type result struct {
	stdout, stderr string
	exit           int
}

func (f *fixture) run(args ...string) result {
	f.t.Helper()
	f.srv.ResetCommands()
	cmd := exec.Command(binary, append([]string{"--config", f.config}, args...)...)
	cmd.Env = append(os.Environ(), "SCOPEDMAIL_PASSWORD="+testserver.Password)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	exit := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			f.t.Fatal(err)
		}
		exit = ee.ExitCode()
	}
	return result{out.String(), errb.String(), exit}
}

func (r result) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.stdout), v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, r.stdout)
	}
}

func (r result) errCode(t *testing.T) string {
	t.Helper()
	var e struct {
		Error struct{ Code, Message string }
	}
	if err := json.Unmarshal([]byte(r.stderr), &e); err != nil {
		t.Fatalf("stderr is not an error JSON: %v\n%s", err, r.stderr)
	}
	return e.Error.Code
}

func (f *fixture) records() []audit.Record {
	f.t.Helper()
	recs, err := audit.Tail(f.audit, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return recs
}

func (f *fixture) lastRecord() audit.Record {
	f.t.Helper()
	recs := f.records()
	if len(recs) == 0 {
		f.t.Fatal("audit log is empty")
	}
	return recs[len(recs)-1]
}

func (f *fixture) count(mailbox string) uint32 {
	f.t.Helper()
	c, err := f.srv.Client()
	if err != nil {
		f.t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(mailbox, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		f.t.Fatal(err)
	}
	return *st.NumMessages
}

func (f *fixture) unseen(mailbox string) uint32 {
	f.t.Helper()
	c, err := f.srv.Client()
	if err != nil {
		f.t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(mailbox, &imap.StatusOptions{NumUnseen: true}).Wait()
	if err != nil {
		f.t.Fatal(err)
	}
	return *st.NumUnseen
}

func TestMailboxesListsOnlyAllowedNames(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	r := f.run("mailboxes")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	var boxes []struct {
		Name     string
		Messages uint32
		Unseen   uint32
	}
	r.json(t, &boxes)
	var names []string
	for _, b := range boxes {
		names = append(names, b.Name)
	}
	if got := strings.Join(names, ","); got != "Agent,Agent/Sub,INBOX" {
		t.Errorf("names = %s", got)
	}
	for _, leak := range []string{"Private", "Gmail", "All Mail"} {
		if strings.Contains(r.stdout+r.stderr, leak) {
			t.Errorf("output reveals %q", leak)
		}
		if strings.Contains(strings.Join(f.srv.Commands(), "\n"), leak) {
			t.Errorf("a command touched %q", leak)
		}
	}
	if rec := f.lastRecord(); rec.Action != "mailboxes" || rec.Outcome != "ok" || rec.Count != 3 {
		t.Errorf("audit record = %+v", rec)
	}
}

func TestSearchThenReadWithoutSettingSeen(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	before := f.unseen("Agent")

	r := f.run("search", "-m", "Agent", "--subject", "hello")
	if r.exit != 0 {
		t.Fatalf("search exit %d: %s", r.exit, r.stderr)
	}
	var hits []struct {
		UID       uint32
		MessageID string `json:"message_id"`
		From      []string
		Subject   string
		Flags     []string
		Size      int
	}
	r.json(t, &hits)
	if len(hits) != 1 || hits[0].UID != 1 || hits[0].Subject != "Agent hello" || hits[0].From[0] != `"Alice" <alice@example.test>` {
		t.Fatalf("hits = %+v", hits)
	}

	r = f.run("read", "-m", "Agent", "1")
	if r.exit != 0 {
		t.Fatalf("read exit %d: %s", r.exit, r.stderr)
	}
	var msg struct {
		UID         uint32
		Subject     string
		Text        string
		Attachments []any
	}
	r.json(t, &msg)
	if msg.UID != 1 || !strings.Contains(msg.Text, testserver.AgentBodyMarker) || len(msg.Attachments) != 0 {
		t.Errorf("message = %+v", msg)
	}
	cmds := strings.Join(f.srv.Commands(), "\n")
	if !strings.Contains(cmds, "EXAMINE") || strings.Contains(cmds, "SELECT") || !strings.Contains(cmds, "BODY.PEEK") {
		t.Errorf("read must EXAMINE and BODY.PEEK:\n%s", cmds)
	}
	if after := f.unseen("Agent"); after != before {
		t.Errorf("unseen %d -> %d: read set \\Seen", before, after)
	}
}

func TestDeniedReadExits3MakesNoIMAPCallAndIsAudited(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	for _, mailbox := range []string{"Private", "[Gmail]/All Mail", "[Google Mail]/All Mail"} {
		r := f.run("read", "-m", mailbox, "1")
		if r.exit != 3 {
			t.Fatalf("%s: exit %d, want 3 (stderr %s)", mailbox, r.exit, r.stderr)
		}
		if code := r.errCode(t); code != "denied" {
			t.Errorf("%s: code = %q", mailbox, code)
		}
		if r.stdout != "" {
			t.Errorf("%s: denied read printed to stdout: %q", mailbox, r.stdout)
		}
		if cmds := f.srv.Commands(); len(cmds) != 0 {
			t.Errorf("%s: denied read sent IMAP commands: %v", mailbox, cmds)
		}
		rec := f.lastRecord()
		if rec.Outcome != "denied" || rec.Action != "read" || rec.Mailbox != mailbox || rec.Reason == "" {
			t.Errorf("%s: record = %+v", mailbox, rec)
		}
	}
	if _, err := audit.Verify(f.audit); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

func TestGmailSystemFolderNeedsExactAllow(t *testing.T) {
	f := newFixture(t, `allow = ["Agent", "[Gmail]/All Mail"]`)
	r := f.run("read", "-m", "[Gmail]/All Mail", "1")
	if r.exit != 0 {
		t.Fatalf("exact allow: exit %d: %s", r.exit, r.stderr)
	}
	if !strings.Contains(r.stdout, testserver.AllMailBodyMarker) {
		t.Errorf("stdout = %s", r.stdout)
	}
	if r := f.run("read", "-m", "[Gmail]/Trash", "1"); r.exit != 3 {
		t.Errorf("sibling system folder: exit %d, want 3", r.exit)
	}
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", `allow = ["Agent", "[Gmail]/*"]`))
	if r := f.run("mailboxes"); r.exit != 1 || r.errCode(t) != "config" {
		t.Errorf("wildcard over Gmail namespace: exit %d stderr %s", r.exit, r.stderr)
	}
}

func TestCopyAndMoveToDisallowedTargetAreDenied(t *testing.T) {
	f := newFixture(t, readOnlyPolicy+allActions)
	for _, verb := range []string{"copy", "move"} {
		for _, target := range []string{"Private", "[Gmail]/All Mail"} {
			r := f.run(verb, "-m", "Agent", "--to", target, "1")
			if r.exit != 3 {
				t.Fatalf("%s to %s: exit %d (stderr %s)", verb, target, r.exit, r.stderr)
			}
			if cmds := f.srv.Commands(); len(cmds) != 0 {
				t.Errorf("%s to %s sent commands: %v", verb, target, cmds)
			}
			if rec := f.lastRecord(); rec.Outcome != "denied" || rec.Target != target {
				t.Errorf("record = %+v", rec)
			}
		}
	}
	if f.count("Private") != 1 || f.count("Agent") != 2 {
		t.Error("a denied copy or move changed mailbox contents")
	}
}

func TestWriteActionsOffByDefault(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	for _, args := range [][]string{
		{"flag", "-m", "Agent", "--add", "seen", "1"},
		{"delete", "-m", "Agent", "1"},
		{"copy", "-m", "Agent", "--to", "Agent/Sub", "1"},
		{"create-mailbox", "Agent/New"},
	} {
		r := f.run(args...)
		if r.exit != 3 || !strings.Contains(r.stderr, "not enabled") {
			t.Errorf("%v: exit %d stderr %s", args, r.exit, r.stderr)
		}
		if len(f.srv.Commands()) != 0 {
			t.Errorf("%v reached the server", args)
		}
	}
}

func TestWriteActionsWhenEnabled(t *testing.T) {
	f := newFixture(t, readOnlyPolicy+allActions+"\ntrash = \"[Gmail]/Trash\"")
	if r := f.run("flag", "-m", "Agent", "--add", "seen,flagged", "1"); r.exit != 0 {
		t.Fatalf("flag: %d %s", r.exit, r.stderr)
	}
	if f.unseen("Agent") != 0 {
		t.Error("flag --add seen had no effect")
	}
	r := f.run("copy", "-m", "Agent", "--to", "Agent/Sub", "1")
	if r.exit != 0 {
		t.Fatalf("copy: %d %s", r.exit, r.stderr)
	}
	var wr struct {
		OK       bool
		Count    int
		DestUIDs []uint32 `json:"dest_uids"`
	}
	r.json(t, &wr)
	if !wr.OK || wr.Count != 1 || len(wr.DestUIDs) != 1 {
		t.Errorf("copy result = %+v", wr)
	}
	if r := f.run("move", "-m", "Agent", "--to", "Agent/Sub", "2"); r.exit != 0 {
		t.Fatalf("move: %d %s", r.exit, r.stderr)
	}
	if r := f.run("delete", "-m", "Agent", "1"); r.exit != 0 {
		t.Fatalf("delete: %d %s", r.exit, r.stderr)
	}
	if f.count("Agent") != 0 || f.count("Agent/Sub") != 3 || f.count("[Gmail]/Trash") != 1 {
		t.Errorf("counts: Agent=%d Sub=%d Trash=%d", f.count("Agent"), f.count("Agent/Sub"), f.count("[Gmail]/Trash"))
	}
	eml := filepath.Join(f.dir, "draft.eml")
	os.WriteFile(eml, []byte("From: a@example.test\r\nSubject: draft\r\n\r\nhi\r\n"), 0o600)
	if r := f.run("create-mailbox", "Agent/Drafts"); r.exit != 0 {
		t.Fatalf("create-mailbox: %d %s", r.exit, r.stderr)
	}
	if r := f.run("append", "-m", "Agent/Drafts", "--file", eml, "--flags", "draft"); r.exit != 0 {
		t.Fatalf("append: %d %s", r.exit, r.stderr)
	}
	if f.count("Agent/Drafts") != 1 {
		t.Error("append did not store the message")
	}
	if r := f.run("append", "-m", "Private", "--file", eml); r.exit != 3 {
		t.Errorf("append to Private: exit %d", r.exit)
	}
	if _, err := audit.Verify(f.audit); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

func TestAttachmentDownload(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	r := f.run("read", "-m", "Agent", "2")
	var msg struct {
		Attachments []struct {
			Part, Filename, Type string
			Size                 int
		}
	}
	r.json(t, &msg)
	if len(msg.Attachments) != 1 || msg.Attachments[0].Part != "2" || msg.Attachments[0].Filename != "report.txt" {
		t.Fatalf("attachments = %+v", msg.Attachments)
	}
	out := filepath.Join(f.dir, "got.txt")
	if r := f.run("attachment", "-m", "Agent", "2", "--part", "2", "--out", out); r.exit != 0 {
		t.Fatalf("attachment: %d %s", r.exit, r.stderr)
	}
	if b, _ := os.ReadFile(out); string(b) != testserver.AttachmentBytes {
		t.Errorf("file = %q", b)
	}
	if r := f.run("attachment", "-m", "Agent", "2", "--part", "2", "--out", out); r.exit != 1 {
		t.Errorf("overwrite: exit %d, want 1", r.exit)
	}
	if r := f.run("attachment", "-m", "Private", "1", "--part", "1", "--out", filepath.Join(f.dir, "p")); r.exit != 3 {
		t.Errorf("attachment from Private: exit %d", r.exit)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "p")); err == nil {
		t.Error("denied attachment wrote a file")
	}
}

func TestAuditVerifyDetectsEditDeletionAndReorder(t *testing.T) {
	setup := func() *fixture {
		f := newFixture(t, readOnlyPolicy)
		for i := 0; i < 4; i++ {
			f.run("search", "-m", "Agent")
		}
		if r := f.run("audit", "verify"); r.exit != 0 {
			t.Fatalf("clean verify: %d %s", r.exit, r.stderr)
		}
		return f
	}
	lines := func(f *fixture) []string {
		b, _ := os.ReadFile(f.audit)
		return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	write := func(f *fixture, l []string) {
		os.WriteFile(f.audit, []byte(strings.Join(l, "\n")+"\n"), 0o600)
	}
	cases := map[string]struct {
		mutate func([]string) []string
		seq    string
	}{
		"edit": {func(l []string) []string {
			l[1] = strings.Replace(l[1], `"outcome":"ok"`, `"outcome":"no"`, 1)
			return l
		}, "seq 2"},
		"delete":  {func(l []string) []string { return append(l[:1:1], l[2:]...) }, "seq 2"},
		"reorder": {func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }, "seq 2"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup()
			write(f, c.mutate(lines(f)))
			r := f.run("audit", "verify")
			if r.exit != 1 || r.errCode(t) != "audit_broken" || !strings.Contains(r.stderr, c.seq) {
				t.Errorf("exit %d stderr %s, want audit_broken at %s", r.exit, r.stderr, c.seq)
			}
		})
	}
}

func TestAuditVerifyAndTailAppendNothing(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	f.run("mailboxes")
	n := len(f.records())
	var v struct {
		OK      bool
		Records int
		Head    string
	}
	r := f.run("audit", "verify")
	r.json(t, &v)
	if !v.OK || v.Records != n || v.Head == "" {
		t.Errorf("verify = %+v", v)
	}
	var tail []audit.Record
	f.run("audit", "tail", "-n", "5").json(t, &tail)
	f.run("policy")
	if got := len(f.records()); got != n {
		t.Errorf("audit/policy commands appended records: %d -> %d", n, got)
	}
	if len(tail) != n {
		t.Errorf("tail returned %d records, want %d", len(tail), n)
	}
}

func TestPolicyCommandShowsEffectivePolicyWithoutConnecting(t *testing.T) {
	f := newFixture(t, readOnlyPolicy+"\ndeny = [\"Agent/Sub\"]")
	r := f.run("policy")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	var p struct {
		Account string
		Policy  struct {
			Allow, Deny, Actions []string
		}
	}
	r.json(t, &p)
	if p.Account != "work" || len(p.Policy.Allow) != 3 || p.Policy.Deny[0] != "Agent/Sub" || strings.Join(p.Policy.Actions, ",") != "attachment,mailboxes,read,search" {
		t.Errorf("policy = %+v", p)
	}
	if len(f.srv.Commands()) != 0 {
		t.Error("policy connected to the server")
	}
}

func TestAuditFailureFailsClosedBeforeConnecting(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	blocker := filepath.Join(f.dir, "blocker")
	os.WriteFile(blocker, nil, 0o600)
	f.audit = filepath.Join(blocker, "audit.jsonl")
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"SCOPEDMAIL_PASSWORD\"", readOnlyPolicy))
	r := f.run("mailboxes")
	if r.exit != 1 || r.errCode(t) != "audit" || r.stdout != "" {
		t.Fatalf("exit %d stdout %q stderr %s", r.exit, r.stdout, r.stderr)
	}
	if len(f.srv.Commands()) != 0 {
		t.Errorf("server saw commands despite unusable audit log: %v", f.srv.Commands())
	}
}

func TestGroupWritableAuditLogIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits")
	}
	f := newFixture(t, readOnlyPolicy)
	f.run("mailboxes")
	os.Chmod(f.audit, 0o664)
	r := f.run("mailboxes")
	if r.exit != 1 || r.errCode(t) != "audit" || len(f.srv.Commands()) != 0 {
		t.Errorf("exit %d stderr %s cmds %v", r.exit, r.stderr, f.srv.Commands())
	}
}

func TestUnsafeOrInvalidConfigIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		f := newFixture(t, readOnlyPolicy)
		os.Chmod(f.config, 0o666)
		r := f.run("mailboxes")
		if r.exit != 1 || r.errCode(t) != "config" || !strings.Contains(r.stderr, "writable") || len(f.srv.Commands()) != 0 {
			t.Errorf("writable config: exit %d stderr %s", r.exit, r.stderr)
		}
	}
	f := newFixture(t, readOnlyPolicy)
	f.writeConfig(f.accountBlock(`password = "hunter2"`, readOnlyPolicy))
	r := f.run("mailboxes")
	if r.exit != 1 || !strings.Contains(r.stderr, "inline passwords") || strings.Contains(r.stderr, "hunter2") {
		t.Errorf("inline password: exit %d stderr %s", r.exit, r.stderr)
	}
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_env = \"X\"\ninsecure_skip_verify = true", readOnlyPolicy))
	if r := f.run("mailboxes"); r.exit != 1 || !strings.Contains(r.stderr, "unknown key") {
		t.Errorf("skip-verify switch: exit %d stderr %s", r.exit, r.stderr)
	}
}

func TestUntrustedCertificateIsRejected(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	f.writeConfig(f.accountBlock(`password_env = "SCOPEDMAIL_PASSWORD"`, readOnlyPolicy))
	r := f.run("mailboxes")
	if r.exit != 1 {
		t.Fatalf("exit %d, want 1", r.exit)
	}
	if rec := f.lastRecord(); rec.Outcome != "error" {
		t.Errorf("record = %+v", rec)
	}
	if cmds := f.srv.Commands(); len(cmds) != 0 {
		t.Errorf("commands over an unverified channel: %v", cmds)
	}
}

func TestPasswordCmd(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	if runtime.GOOS == "windows" {
		t.Skip("uses a unix shell script")
	}
	script := filepath.Join(f.dir, "pw.sh")
	os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' '"+testserver.Password+"'\n"), 0o700)
	f.writeConfig(f.accountBlock(fmt.Sprintf("tls_ca_file = \"ca.pem\"\npassword_cmd = [%q]", script), readOnlyPolicy))
	if r := f.run("mailboxes"); r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\npassword_cmd = [\"false\"]", readOnlyPolicy))
	r := f.run("mailboxes")
	if r.exit != 1 || strings.Contains(r.stderr, testserver.Password) {
		t.Errorf("failing password_cmd: exit %d stderr %s", r.exit, r.stderr)
	}
}

func TestWrongPasswordIsAnAuditedError(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	cmd := exec.Command(binary, "--config", f.config, "mailboxes")
	cmd.Env = append(os.Environ(), "SCOPEDMAIL_PASSWORD=wrong-password")
	if err := cmd.Run(); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}
	rec := f.lastRecord()
	if rec.Outcome != "error" {
		t.Errorf("record = %+v", rec)
	}
	b, _ := os.ReadFile(f.audit)
	if bytes.Contains(b, []byte("wrong-password")) || bytes.Contains(b, []byte(testserver.Password)) {
		t.Error("audit log contains a password")
	}
}

func TestUsageErrorsExit2(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	for _, args := range [][]string{
		{},
		{"nonsense"},
		{"read", "1"},
		{"read", "-m", "Agent"},
		{"read", "-m", "Agent", "abc"},
		{"search", "-m", "Agent", "--since", "yesterday"},
		{"search", "-m", "Agent", "--seen", "--unseen"},
		{"copy", "-m", "Agent", "1"},
		{"flag", "-m", "Agent", "1"},
		{"audit"},
	} {
		if r := f.run(args...); r.exit != 2 || r.errCode(t) != "usage" {
			t.Errorf("%v: exit %d stderr %s", args, r.exit, r.stderr)
		}
	}
	if _, err := os.Stat(f.audit); err == nil || len(f.srv.Commands()) != 0 {
		t.Error("usage errors must not connect or touch the audit log")
	}
}

func TestAuditNeverHoldsCredentialsOrBodies(t *testing.T) {
	f := newFixture(t, readOnlyPolicy+allActions)
	f.run("read", "-m", "Agent", "1", "--raw")
	f.run("read", "-m", "Private", "1")
	f.run("search", "-m", "Agent", "--text", "hello")
	f.run("mailboxes")
	b, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testserver.Password, testserver.AgentBodyMarker, testserver.PrivateBodyMarker, testserver.AllMailBodyMarker} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	if info, err := os.Stat(f.audit); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("audit mode = %v, %v", info.Mode().Perm(), err)
	}
}

func TestExplicitAccountFlagAndMissingAccount(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	cmd := exec.Command(binary, "--config", f.config, "--account", "missing", "mailboxes")
	cmd.Env = append(os.Environ(), "SCOPEDMAIL_PASSWORD="+testserver.Password)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || !strings.Contains(errb.String(), "unknown account") {
		t.Errorf("err %v stderr %s", err, errb.String())
	}
}
