package cli_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/testserver"
)

const sendPolicy = `allow = ["Agent", "INBOX"]
actions = ["read", "send"]
send_to = ["@example.com", "carol@other.org"]
`

func newSendFixture(t *testing.T, policyBody string, extra string) *fixture {
	t.Helper()
	f := newFixture(t, readOnlyPolicy)
	smtpSrv, err := testserver.StartSMTP(testserver.SMTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { smtpSrv.Close() })
	f.smtp = smtpSrv
	bundle := append(append([]byte(nil), f.srv.CAPEM...), smtpSrv.CAPEM...)
	if err := os.WriteFile(filepath.Join(f.dir, "ca.pem"), bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if extra == "" {
		extra = "password_env = \"SCOPEDMAIL_PASSWORD\""
	}
	f.writeConfig(f.accountBlock("tls_ca_file = \"ca.pem\"\n"+extra, policyBody+fmt.Sprintf(`
[accounts.work.smtp]
host = %q
port = %d
`, smtpSrv.Host, smtpSrv.Port)))
	return f
}

type parsedMail struct {
	header mail.Header
	texts  []string
	atts   map[string]string
}

func parseMail(t *testing.T, data []byte) parsedMail {
	t.Helper()
	r, err := mail.CreateReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, data)
	}
	pm := parsedMail{header: r.Header, atts: map[string]string{}}
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			return pm
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p.Body)
		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := h.ContentType()
			pm.texts = append(pm.texts, ct+"|"+strings.TrimSpace(string(b)))
		case *mail.AttachmentHeader:
			name, _ := h.Filename()
			pm.atts[name] = string(b)
		}
	}
}

func (f *fixture) auditRaw() string {
	f.t.Helper()
	b, err := os.ReadFile(f.audit)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func TestSendDeliversAndAuditsWithoutText(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	dir := t.TempDir()
	htmlPath, attPath := filepath.Join(dir, "m.html"), filepath.Join(dir, "report.csv")
	os.WriteFile(htmlPath, []byte("<p>HTML-BODY-MARKER</p>"), 0o600)
	os.WriteFile(attPath, []byte("a,b\n1,2\n"), 0o600)

	r := f.runIn("STDIN-BODY-MARKER hello\n", "send", "--to", "Alice <alice@example.com>", "--cc", "carol@other.org",
		"--bcc", "hidden@example.com", "--subject", "SUBJECT-MARKER lunch", "--html-file", htmlPath, "--attach", attPath)
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	var out struct {
		OK         bool
		MessageID  string `json:"message_id"`
		Recipients []string
	}
	r.json(t, &out)
	if !out.OK || out.MessageID == "" || strings.Join(out.Recipients, ",") != "alice@example.com,carol@other.org,hidden@example.com" {
		t.Errorf("output = %+v", out)
	}

	ds := f.smtp.Deliveries()
	if len(ds) != 1 {
		t.Fatalf("deliveries = %d", len(ds))
	}
	d := ds[0]
	if d.From != testserver.Username || strings.Join(d.To, ",") != "alice@example.com,carol@other.org,hidden@example.com" {
		t.Errorf("envelope from=%q to=%v", d.From, d.To)
	}
	pm := parseMail(t, d.Data)
	if from, _ := pm.header.AddressList("From"); len(from) != 1 || from[0].Address != testserver.Username {
		t.Errorf("From = %v", from)
	}
	if id, _ := pm.header.MessageID(); id != out.MessageID {
		t.Errorf("Message-ID = %q, output %q", id, out.MessageID)
	}
	if subj, _ := pm.header.Subject(); subj != "SUBJECT-MARKER lunch" {
		t.Errorf("subject = %q", subj)
	}
	if pm.header.Has("Bcc") || bytes.Contains(d.Data, []byte("hidden@example.com")) {
		t.Error("Bcc leaked into the message")
	}
	if len(pm.texts) != 2 || pm.texts[0] != "text/plain|STDIN-BODY-MARKER hello" || pm.texts[1] != "text/html|<p>HTML-BODY-MARKER</p>" {
		t.Errorf("texts = %q", pm.texts)
	}
	if pm.atts["report.csv"] != "a,b\n1,2\n" {
		t.Errorf("attachments = %v", pm.atts)
	}

	rec := f.lastRecord()
	if rec.Action != "send" || rec.Outcome != audit.OutcomeOK || rec.Args["message_id"] != out.MessageID {
		t.Errorf("record = %+v", rec)
	}
	if rec.Args["to"] != "alice@example.com" || rec.Args["bcc"] != "hidden@example.com" || rec.Args["attachments"] != `"report.csv":8` {
		t.Errorf("args = %v", rec.Args)
	}
	if len(rec.Args["sha256"]) != 64 || len(rec.Args["subject_sha256"]) != 64 {
		t.Errorf("hashes missing: %v", rec.Args)
	}
	raw := f.auditRaw()
	for _, secret := range []string{"STDIN-BODY-MARKER", "HTML-BODY-MARKER", "SUBJECT-MARKER", "a,b", testserver.Password} {
		if strings.Contains(raw, secret) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	if v := f.run("audit", "verify"); v.exit != 0 {
		t.Errorf("audit verify: %d %s", v.exit, v.stderr)
	}
}

func TestSendBodyFromFileAndFlag(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	path := filepath.Join(t.TempDir(), "body.txt")
	os.WriteFile(path, []byte("from a file"), 0o600)
	for _, args := range [][]string{
		{"send", "--to", "a@example.com", "--subject", "s", "--body-file", path},
		{"send", "--to", "a@example.com", "--subject", "s", "--body", "from a flag"},
	} {
		if r := f.run(args...); r.exit != 0 {
			t.Fatalf("%v: exit %d %s", args, r.exit, r.stderr)
		}
	}
	ds := f.smtp.Deliveries()
	if len(ds) != 2 || parseMail(t, ds[0].Data).texts[0] != "text/plain|from a file" || parseMail(t, ds[1].Data).texts[0] != "text/plain|from a flag" {
		t.Errorf("deliveries = %d", len(ds))
	}
	if r := f.run("send", "--to", "a@example.com", "--subject", "s", "--body", "x", "--body-file", path); r.exit != 2 {
		t.Errorf("--body with --body-file: exit %d", r.exit)
	}
}

func TestSendDeniedRecipientNeverConnectsOrRunsCredentialCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "credential-ran")
	cmd := fmt.Sprintf(`password_cmd = ["/bin/sh", "-c", "touch %s; printf %%s %s"]`, marker, testserver.Password)
	f := newSendFixture(t, sendPolicy, cmd)

	for name, args := range map[string][]string{
		"to":        {"--to", "evil@attacker.test"},
		"cc":        {"--to", "a@example.com", "--cc", "evil@attacker.test"},
		"bcc":       {"--to", "a@example.com", "--bcc", "evil@attacker.test"},
		"subdomain": {"--to", "a@mail.example.com"},
		"lookalike": {"--to", "example.com@attacker.test"},
	} {
		t.Run(name, func(t *testing.T) {
			r := f.run(append([]string{"send", "--subject", "s", "--body", "b"}, args...)...)
			if r.exit != 3 || r.errCode(t) != "denied" {
				t.Fatalf("exit %d code %s: %s", r.exit, r.errCode(t), r.stderr)
			}
			if !strings.Contains(r.stderr, "attacker.test") && !strings.Contains(r.stderr, "mail.example.com") {
				t.Errorf("denial does not name the address: %s", r.stderr)
			}
			if f.smtp.Connections() != 0 || len(f.srv.Commands()) != 0 {
				t.Errorf("connections: smtp=%d imap=%v", f.smtp.Connections(), f.srv.Commands())
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("credential command ran for a denied send")
			}
			if rec := f.lastRecord(); rec.Action != "send" || rec.Outcome != audit.OutcomeDenied {
				t.Errorf("record = %+v", rec)
			}
		})
	}
	if v := f.run("audit", "verify"); v.exit != 0 {
		t.Errorf("audit verify: %d %s", v.exit, v.stderr)
	}
}

func TestSendIsDeniedUnlessEnabled(t *testing.T) {
	f := newSendFixture(t, `allow = ["Agent"]
send_to = ["@example.com"]
`, "")
	r := f.run("send", "--to", "a@example.com", "--subject", "s", "--body", "b")
	if r.exit != 3 || f.smtp.Connections() != 0 {
		t.Errorf("exit %d conns %d: %s", r.exit, f.smtp.Connections(), r.stderr)
	}
}

func TestSendRejectsHeaderInjectionAndForbiddenFlags(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	good := []string{"send", "--to", "a@example.com", "--subject", "s", "--body", "b"}
	with := func(flag, val string) []string {
		return append(append([]string(nil), good...), flag, val)
	}
	for name, args := range map[string][]string{
		"crlf subject": {"send", "--to", "a@example.com", "--subject", "hi\r\nBcc: evil@attacker.test", "--body", "b"},
		"lf subject":   {"send", "--to", "a@example.com", "--subject", "hi\nX-Evil: 1", "--body", "b"},
		"crlf to":      {"send", "--to", "a@example.com\r\nBcc: evil@attacker.test", "--subject", "s", "--body", "b"},
		"crlf cc":      {"send", "--to", "a@example.com", "--cc", "b@example.com\nX: y", "--subject", "s", "--body", "b"},
		"crlf attach":  with("--attach", "x\r\ny"),
		"from flag":    with("--from", "ceo@example.com"),
		"header flag":  with("--header", "X-Evil: 1"),
		"sender flag":  with("--sender", "ceo@example.com"),
		"raw flag":     with("--raw", "x.eml"),
		"no recipient": {"send", "--subject", "s", "--body", "b"},
		"no subject":   {"send", "--to", "a@example.com", "--body", "b"},
		"unparsable":   {"send", "--to", "not an address", "--subject", "s", "--body", "b"},
	} {
		r := f.run(args...)
		if r.exit != 2 || r.errCode(t) != "usage" {
			t.Errorf("%s: exit %d stderr %s", name, r.exit, r.stderr)
		}
	}
	if f.smtp.Connections() != 0 || len(f.smtp.Deliveries()) != 0 {
		t.Error("a rejected send reached the SMTP server")
	}
}

func TestSendReplyThreadsAndChecksTheMailbox(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	r := f.run("send", "--reply-to", "-m", "Agent", "1", "--to", "alice@example.com", "--body", "got it")
	if r.exit != 0 {
		t.Fatalf("exit %d: %s", r.exit, r.stderr)
	}
	d := f.smtp.Deliveries()[0]
	pm := parseMail(t, d.Data)
	if subj, _ := pm.header.Subject(); subj != "Re: Agent hello" {
		t.Errorf("subject = %q", subj)
	}
	if irt, _ := pm.header.MsgIDList("In-Reply-To"); len(irt) != 1 || irt[0] != "agent-1@example.test" {
		t.Errorf("In-Reply-To = %v", irt)
	}
	if refs, _ := pm.header.MsgIDList("References"); len(refs) != 1 || refs[0] != "agent-1@example.test" {
		t.Errorf("References = %v", refs)
	}
	if len(d.To) != 1 || d.To[0] != "alice@example.com" {
		t.Errorf("a reply must not add recipients: %v", d.To)
	}
	if rec := f.lastRecord(); rec.Action != "send" || rec.Mailbox != "Agent" || len(rec.UIDs) != 1 || rec.UIDs[0] != 1 {
		t.Errorf("record = %+v", rec)
	}

	before := f.smtp.Connections()
	r = f.run("send", "--reply-to", "-m", "Private", "1", "--to", "alice@example.com", "--body", "leak")
	if r.exit != 3 || r.errCode(t) != "denied" {
		t.Fatalf("reply to a denied mailbox: exit %d %s", r.exit, r.stderr)
	}
	if f.smtp.Connections() != before || len(f.srv.Commands()) != 0 {
		t.Errorf("denied reply connected: smtp %d->%d imap=%v", before, f.smtp.Connections(), f.srv.Commands())
	}
	if rec := f.lastRecord(); rec.Action != "send" || rec.Outcome != audit.OutcomeDenied || rec.Mailbox != "Private" {
		t.Errorf("record = %+v", rec)
	}
	if strings.Contains(f.auditRaw(), testserver.PrivateBodyMarker) {
		t.Error("audit log holds the denied message")
	}
	if len(f.smtp.Deliveries()) != 1 {
		t.Errorf("deliveries = %d, want only the allowed reply", len(f.smtp.Deliveries()))
	}
}

func TestSendRecipientsAppearInPolicyOutput(t *testing.T) {
	f := newSendFixture(t, sendPolicy, "")
	r := f.run("policy")
	if r.exit != 0 || !strings.Contains(r.stdout, `"send_to":["@example.com","carol@other.org"]`) || !strings.Contains(r.stdout, `"max_recipients":10`) {
		t.Errorf("policy output: %s", r.stdout)
	}
}
