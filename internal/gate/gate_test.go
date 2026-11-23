package gate_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/config"
	"github.com/momirov/scopedmail/internal/gate"
	"github.com/momirov/scopedmail/internal/policy"
	"github.com/momirov/scopedmail/internal/testserver"
)

type env struct {
	srv  *testserver.Server
	sess *gate.Session
	log  string
}

func setup(t *testing.T, spec policy.Spec, opts testserver.Options) *env {
	t.Helper()
	srv, err := testserver.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, srv.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GATE_TEST_PW", testserver.Password)
	pol, err := policy.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	acct := config.Account{
		Name: "test", Host: srv.Host, Port: srv.Port, Username: testserver.Username,
		StartTLS: opts.StartTLS, TLSCAFile: ca, Auth: config.AuthPassword, PasswordEnv: "GATE_TEST_PW", Policy: pol,
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	sess := gate.New("test", pol, log, gate.Dialer(acct))
	t.Cleanup(func() { sess.Close(); log.Close() })
	return &env{srv: srv, sess: sess, log: logPath}
}

func (e *env) records(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := audit.Tail(e.log, 0)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func (e *env) commands() string { return strings.Join(e.srv.Commands(), "\n") }

func (e *env) unseen(t *testing.T, mailbox string) uint32 {
	t.Helper()
	c, err := e.srv.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(mailbox, &imap.StatusOptions{NumUnseen: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return *st.NumUnseen
}

func (e *env) count(t *testing.T, mailbox string) uint32 {
	t.Helper()
	c, err := e.srv.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	st, err := c.Status(mailbox, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return *st.NumMessages
}

var allActions = []string{"mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox"}

func TestMailboxesHidesDisallowedNames(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent", "Agent/*", "INBOX"}}, testserver.Options{})
	boxes, err := e.sess.Mailboxes()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, b := range boxes {
		names = append(names, b.Name)
	}
	if got, want := strings.Join(names, ","), "Agent,Agent/Sub,INBOX"; got != want {
		t.Errorf("mailboxes = %s, want %s", got, want)
	}
	if strings.Contains(e.commands(), "Private") || strings.Contains(e.commands(), "Gmail") {
		t.Errorf("a command touched a disallowed mailbox:\n%s", e.commands())
	}
	for _, b := range boxes {
		if b.Name == "Agent" && (b.Messages != 2 || b.Unseen != 1) {
			t.Errorf("Agent counts = %+v, want 2 messages 1 unseen", b)
		}
	}
}

func TestDeniedActionSendsNothingAndIsAudited(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	_, err := e.sess.Read("Private", 1, gate.ReadOptions{})
	var denied *gate.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("err = %v, want DeniedError", err)
	}
	if cmds := e.srv.Commands(); len(cmds) != 0 {
		t.Errorf("denied read reached the server: %v", cmds)
	}
	recs := e.records(t)
	if len(recs) != 1 || recs[0].Outcome != audit.OutcomeDenied || recs[0].Action != "read" || recs[0].Mailbox != "Private" {
		t.Errorf("records = %+v", recs)
	}
}

func TestReadNeverSetsSeen(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	before := e.unseen(t, "Agent")
	e.srv.ResetCommands()
	msg, err := e.sess.Read("Agent", 1, gate.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, testserver.AgentBodyMarker) {
		t.Errorf("text = %q", msg.Text)
	}
	cmds := e.commands()
	if !strings.Contains(cmds, "EXAMINE") || strings.Contains(cmds, "SELECT") {
		t.Errorf("read must EXAMINE, not SELECT:\n%s", cmds)
	}
	if !strings.Contains(cmds, "BODY.PEEK[1]") || strings.Contains(strings.ReplaceAll(cmds, "BODY.PEEK", ""), "BODY[") {
		t.Errorf("read must use BODY.PEEK only:\n%s", cmds)
	}
	if after := e.unseen(t, "Agent"); after != before {
		t.Errorf("unseen count changed from %d to %d: read set \\Seen", before, after)
	}
}

func TestReadMultipartDecodesAndListsAttachments(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	msg, err := e.sess.Read("Agent", 2, gate.ReadOptions{HTML: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, "Report attached — see the file.") {
		t.Errorf("quoted-printable not decoded: %q", msg.Text)
	}
	if !strings.Contains(msg.HTML, "<p>Report attached</p>") {
		t.Errorf("html = %q", msg.HTML)
	}
	if len(msg.Attachments) != 1 || msg.Attachments[0].Part != "2" || msg.Attachments[0].Filename != "report.txt" {
		t.Errorf("attachments = %+v", msg.Attachments)
	}
	if len(msg.Cc) != 1 || msg.Subject != "Quarterly report" {
		t.Errorf("summary = %+v", msg.Summary)
	}
}

func TestAttachmentWritesDecodedBytesAndRefusesOverwrite(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	out := filepath.Join(t.TempDir(), "report.txt")
	res, err := e.sess.Attachment("Agent", 2, "2", out)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != testserver.AttachmentBytes || res.Bytes != int64(len(got)) {
		t.Errorf("file = %q, result = %+v", got, res)
	}
	if info, _ := os.Stat(out); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	if _, err := e.sess.Attachment("Agent", 2, "2", out); err == nil {
		t.Error("second write over an existing file succeeded")
	}
	if _, err := e.sess.Attachment("Agent", 2, "9", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Error("nonexistent part succeeded")
	}
}

func TestSearchReturnsNewestFirstAndRespectsLimit(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	all, err := e.sess.Search("Agent", gate.SearchQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].UID != 2 || all[1].UID != 1 {
		t.Fatalf("all = %+v", all)
	}
	one, err := e.sess.Search("Agent", gate.SearchQuery{Limit: 1})
	if err != nil || len(one) != 1 || one[0].UID != 2 {
		t.Fatalf("limit 1 = %+v, %v", one, err)
	}
	bySubject, err := e.sess.Search("Agent", gate.SearchQuery{Subject: "hello", Limit: 10})
	if err != nil || len(bySubject) != 1 || bySubject[0].Subject != "Agent hello" || bySubject[0].MessageID != "agent-1@example.test" {
		t.Fatalf("subject search = %+v, %v", bySubject, err)
	}
	unseen, err := e.sess.Search("Agent", gate.SearchQuery{Seen: gate.UnseenOnly, Limit: 10})
	if err != nil || len(unseen) != 1 || unseen[0].UID != 1 {
		t.Fatalf("unseen search = %+v, %v", unseen, err)
	}
	none, err := e.sess.Search("Agent", gate.SearchQuery{Subject: "nonexistent-zzz", Limit: 10})
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("empty search = %#v, %v", none, err)
	}
}

func TestCopyAndMoveTargetsAreEnforced(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent", "Agent/*"}, Actions: allActions}, testserver.Options{})
	e.srv.ResetCommands()
	for _, target := range []string{"Private", "[Gmail]/All Mail"} {
		var denied *gate.DeniedError
		if _, err := e.sess.Copy("Agent", target, []uint32{1}); !errors.As(err, &denied) {
			t.Errorf("copy to %s: err = %v, want denied", target, err)
		}
		if _, err := e.sess.Move("Agent", target, []uint32{1}); !errors.As(err, &denied) {
			t.Errorf("move to %s: err = %v, want denied", target, err)
		}
	}
	if cmds := e.srv.Commands(); len(cmds) != 0 {
		t.Errorf("denied copies reached the server: %v", cmds)
	}
	if n := e.count(t, "Private"); n != 1 {
		t.Errorf("Private has %d messages, want 1", n)
	}
	dest, err := e.sess.Copy("Agent", "Agent/Sub", []uint32{1})
	if err != nil || len(dest) != 1 {
		t.Fatalf("allowed copy = %v, %v", dest, err)
	}
	if n := e.count(t, "Agent/Sub"); n != 2 {
		t.Errorf("Agent/Sub has %d messages, want 2", n)
	}
	if _, err := e.sess.Move("Agent", "Agent/Sub", []uint32{2}); err != nil {
		t.Fatal(err)
	}
	if e.count(t, "Agent") != 1 || e.count(t, "Agent/Sub") != 3 {
		t.Error("move did not transfer the message")
	}
	if got := e.records(t); got[len(got)-1].Outcome != audit.OutcomeOK || got[len(got)-1].Target != "Agent/Sub" {
		t.Errorf("last record = %+v", got[len(got)-1])
	}
}

func TestDeleteMovesToTrashSink(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions, Trash: "[Gmail]/Trash"}, testserver.Options{})
	if err := e.sess.Delete("Agent", []uint32{1}); err != nil {
		t.Fatal(err)
	}
	if e.count(t, "Agent") != 1 || e.count(t, "[Gmail]/Trash") != 1 {
		t.Errorf("agent=%d trash=%d, want 1 and 1", e.count(t, "Agent"), e.count(t, "[Gmail]/Trash"))
	}
	var denied *gate.DeniedError
	if _, err := e.sess.Read("[Gmail]/Trash", 1, gate.ReadOptions{}); !errors.As(err, &denied) {
		t.Errorf("trash sink became readable: %v", err)
	}
}

func TestDeleteWithoutTrashExpungesOnlyTheNamedUIDs(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions}, testserver.Options{})
	// Another client's \Deleted message must survive: only UID 1 may go.
	c, err := e.srv.Client()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("Agent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(imap.UIDSetNum(2), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := e.sess.Delete("Agent", []uint32{1}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "Agent"); n != 1 {
		t.Errorf("Agent has %d messages, want 1 (UID 2 must survive)", n)
	}
	cmds := e.commands()
	if !strings.Contains(cmds, "UID EXPUNGE") || strings.Contains(strings.ReplaceAll(cmds, "UID EXPUNGE", ""), "EXPUNGE") {
		t.Errorf("must use UID EXPUNGE only:\n%s", cmds)
	}
}

func TestMoveWithoutMoveCapabilityCopiesThenExpunges(t *testing.T) {
	caps := imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}}
	e := setup(t, policy.Spec{Allow: []string{"Agent", "Agent/*"}, Actions: allActions}, testserver.Options{Caps: caps})
	if _, err := e.sess.Move("Agent", "Agent/Sub", []uint32{1}); err != nil {
		t.Fatal(err)
	}
	if e.count(t, "Agent") != 1 || e.count(t, "Agent/Sub") != 2 {
		t.Error("fallback move did not transfer the message")
	}
}

func TestMoveWithoutMoveOrUIDPlusRefuses(t *testing.T) {
	caps := imap.CapSet{imap.CapIMAP4rev1: {}}
	e := setup(t, policy.Spec{Allow: []string{"Agent", "Agent/*"}, Actions: allActions}, testserver.Options{Caps: caps})
	if _, err := e.sess.Move("Agent", "Agent/Sub", []uint32{1}); err == nil {
		t.Fatal("move succeeded without MOVE or UIDPLUS")
	}
	if e.count(t, "Agent") != 2 || e.count(t, "Agent/Sub") != 1 {
		t.Error("a refused move changed mailbox contents")
	}
	if got := e.records(t); got[len(got)-1].Outcome != audit.OutcomeError {
		t.Errorf("record = %+v, want error outcome", got[len(got)-1])
	}
}

func TestFlagAddRemoveAndRefusesDeleted(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions}, testserver.Options{})
	if err := e.sess.Flag("Agent", []uint32{1}, []string{"seen", "flagged", "Reviewed"}, nil); err != nil {
		t.Fatal(err)
	}
	if e.unseen(t, "Agent") != 0 {
		t.Error("seen flag was not set")
	}
	if err := e.sess.Flag("Agent", []uint32{1}, nil, []string{"seen"}); err != nil {
		t.Fatal(err)
	}
	if e.unseen(t, "Agent") != 1 {
		t.Error("seen flag was not removed")
	}
	before := len(e.records(t))
	var usage *gate.UsageError
	for _, bad := range []string{`\Deleted`, "deleted", `\Recent`, "a b", ""} {
		if err := e.sess.Flag("Agent", []uint32{1}, []string{bad}, nil); !errors.As(err, &usage) {
			t.Errorf("flag %q: err = %v, want UsageError", bad, err)
		}
	}
	if len(e.records(t)) != before {
		t.Error("usage errors must not be audited as attempts")
	}
}

func TestAppendAndCreateMailbox(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent", "Agent/*"}, Actions: allActions}, testserver.Options{})
	if err := e.sess.CreateMailbox("Agent/New"); err != nil {
		t.Fatal(err)
	}
	var denied *gate.DeniedError
	if err := e.sess.CreateMailbox("Elsewhere"); !errors.As(err, &denied) {
		t.Errorf("create outside allowlist: %v", err)
	}
	raw := "From: a@example.test\r\nSubject: drafted\r\n\r\nbody\r\n"
	uid, err := e.sess.Append("Agent/New", strings.NewReader(raw), int64(len(raw)), []string{"draft"}, "draft.eml")
	if err != nil || uid == 0 {
		t.Fatalf("append = %d, %v", uid, err)
	}
	if e.count(t, "Agent/New") != 1 {
		t.Error("appended message missing")
	}
	r := bytes.NewReader([]byte("x"))
	if _, err := e.sess.Append("Private", r, 1, nil, ""); !errors.As(err, &denied) {
		t.Errorf("append to Private: %v", err)
	}
	if r.Len() != 1 {
		t.Error("denied append consumed its input")
	}
}

func TestAuditHoldsNoBodiesOrCredentials(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions}, testserver.Options{})
	if _, err := e.sess.Read("Agent", 1, gate.ReadOptions{Raw: true}); err != nil {
		t.Fatal(err)
	}
	e.sess.Search("Agent", gate.SearchQuery{Text: "x", Limit: 5})
	e.sess.Read("Private", 1, gate.ReadOptions{})
	b, err := os.ReadFile(e.log)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testserver.Password, testserver.AgentBodyMarker, testserver.PrivateBodyMarker} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("audit log contains %q", secret)
		}
	}
}

func TestFailedAuditAppendWithholdsResults(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	log, err := audit.Open(e.log)
	if err != nil {
		t.Fatal(err)
	}
	log.Close() // appends to a closed log fail
	sess := gate.New("test", mustPolicy(t, policy.Spec{Allow: []string{"Agent"}}), log, func() (*imapclient.Client, error) { return nil, errors.New("must not connect") })
	_, err = sess.Search("Agent", gate.SearchQuery{Limit: 1})
	var ae *gate.AuditError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want AuditError", err)
	}
}

func mustPolicy(t *testing.T, s policy.Spec) policy.Policy {
	t.Helper()
	p, err := policy.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStartTLSConnection(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{StartTLS: true})
	if _, err := e.sess.Search("Agent", gate.SearchQuery{Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.commands(), "STARTTLS") {
		t.Errorf("commands:\n%s", e.commands())
	}
}

func TestUntrustedServerCertificateFailsClosed(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	pol := mustPolicy(t, policy.Spec{Allow: []string{"Agent"}})
	log, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer log.Close()
	acct := config.Account{Host: e.srv.Host, Port: e.srv.Port, Username: testserver.Username, Auth: config.AuthPassword, PasswordEnv: "GATE_TEST_PW", Policy: pol}
	sess := gate.New("x", pol, log, gate.Dialer(acct))
	if _, err := sess.Mailboxes(); err == nil {
		t.Fatal("connected to a server whose certificate is not trusted")
	}
}
