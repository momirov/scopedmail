package gate_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/config"
	"github.com/momirov/scopedmail/internal/gate"
	"github.com/momirov/scopedmail/internal/policy"
	"github.com/momirov/scopedmail/internal/testserver"
)

type sendEnv struct {
	*env
	smtp *testserver.SMTPServer
}

func setupSend(t *testing.T, smtpOpts testserver.SMTPOptions, spec policy.Spec) *sendEnv {
	t.Helper()
	imapSrv, err := testserver.Start(testserver.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { imapSrv.Close() })
	smtpSrv, err := testserver.StartSMTP(smtpOpts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { smtpSrv.Close() })

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, append(append([]byte(nil), imapSrv.CAPEM...), smtpSrv.CAPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GATE_TEST_PW", testserver.Password)
	pol := mustPolicy(t, spec)
	acct := config.Account{
		Name: "test", Host: imapSrv.Host, Port: imapSrv.Port, Username: testserver.Username,
		TLSCAFile: ca, Auth: config.AuthPassword, PasswordEnv: "GATE_TEST_PW", Policy: pol,
		SMTP: config.SMTP{Host: smtpSrv.Host, Port: smtpSrv.Port, StartTLS: smtpOpts.StartTLS},
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	sess := gate.New("test", pol, log, gate.Dialer(acct), gate.SMTPOutbound(acct), nil)
	t.Cleanup(func() { sess.Close(); log.Close() })
	return &sendEnv{env: &env{srv: imapSrv, sess: sess, log: logPath}, smtp: smtpSrv}
}

var sendSpec = policy.Spec{
	Allow:   []string{"Agent", "INBOX"},
	Actions: []string{"read", "send"},
	SendTo:  []string{"@example.com", "carol@other.org"},
}

func parseDelivery(t *testing.T, data []byte) (mail.Header, []string, map[string][]byte) {
	t.Helper()
	r, err := mail.CreateReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse delivery: %v\n%s", err, data)
	}
	var bodies []string
	atts := map[string][]byte{}
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p.Body)
		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			ct, _, _ := h.ContentType()
			bodies = append(bodies, ct+"|"+strings.TrimSpace(string(b)))
		case *mail.AttachmentHeader:
			name, _ := h.Filename()
			atts[name] = b
		}
	}
	return r.Header, bodies, atts
}

func TestSendDeliversWithFixedFromAndBccOnlyInEnvelope(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	res, err := e.sess.Send(gate.Outgoing{
		To:          []string{"Alice@Example.com"},
		Cc:          []string{"carol@other.org"},
		Bcc:         []string{"bob@example.com", "alice@example.com"},
		Subject:     "SUBJECT-SECRET-TEXT",
		Text:        "BODY-SECRET-TEXT héllo\nsecond line",
		HTML:        "<p>HTML-SECRET</p>",
		Attachments: []gate.Attachment{{Name: "notes.txt", Data: []byte("attached bytes")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.Recipients, ","); got != "Alice@Example.com,carol@other.org,bob@example.com" {
		t.Errorf("recipients = %s", got)
	}
	ds := e.smtp.Deliveries()
	if len(ds) != 1 {
		t.Fatalf("deliveries = %d", len(ds))
	}
	d := ds[0]
	if d.AuthUser != testserver.Username || d.From != testserver.Username {
		t.Errorf("auth=%q from=%q", d.AuthUser, d.From)
	}
	if got := strings.Join(d.To, ","); got != "Alice@Example.com,carol@other.org,bob@example.com" {
		t.Errorf("envelope = %s", got)
	}
	h, bodies, atts := parseDelivery(t, d.Data)
	if from, _ := h.AddressList("From"); len(from) != 1 || from[0].Address != testserver.Username {
		t.Errorf("From header = %v", from)
	}
	if to, _ := h.AddressList("To"); len(to) != 1 || to[0].Address != "Alice@Example.com" {
		t.Errorf("To header = %v", to)
	}
	if cc, _ := h.AddressList("Cc"); len(cc) != 1 || cc[0].Address != "carol@other.org" {
		t.Errorf("Cc header = %v", cc)
	}
	if bytes.Contains(d.Data, []byte("bob@example.com")) || h.Has("Bcc") {
		t.Errorf("a Bcc address leaked into the message headers:\n%s", d.Data)
	}
	if subj, _ := h.Subject(); subj != "SUBJECT-SECRET-TEXT" {
		t.Errorf("subject = %q", subj)
	}
	if id, _ := h.MessageID(); id != res.MessageID || !strings.HasSuffix(id, "@example.test") {
		t.Errorf("Message-ID = %q, result %q", id, res.MessageID)
	}
	if len(bodies) != 2 || bodies[0] != "text/plain|BODY-SECRET-TEXT héllo\r\nsecond line" || bodies[1] != "text/html|<p>HTML-SECRET</p>" {
		t.Errorf("bodies = %q", bodies)
	}
	if string(atts["notes.txt"]) != "attached bytes" {
		t.Errorf("attachments = %v", atts)
	}

	recs := e.records(t)
	if len(recs) != 1 || recs[0].Action != "send" || recs[0].Outcome != audit.OutcomeOK {
		t.Fatalf("records = %+v", recs)
	}
	a := recs[0].Args
	if a["to"] != "Alice@Example.com" || a["cc"] != "carol@other.org" || a["bcc"] != "bob@example.com,alice@example.com" {
		t.Errorf("args = %v", a)
	}
	if a["message_id"] != res.MessageID || a["attachments"] != `"notes.txt":14` || len(a["sha256"]) != 64 || len(a["subject_sha256"]) != 64 {
		t.Errorf("args = %v", a)
	}
	raw, _ := os.ReadFile(e.log)
	for _, secret := range []string{"SUBJECT-SECRET-TEXT", "BODY-SECRET-TEXT", "HTML-SECRET", "attached bytes"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("audit log contains %q", secret)
		}
	}
	if cmds := e.commands(); cmds != "" {
		t.Errorf("a plain send touched IMAP: %s", cmds)
	}
}

func TestSendDeniedByAnyRecipientSendsNothing(t *testing.T) {
	for name, out := range map[string]gate.Outgoing{
		"to":        {To: []string{"alice@example.com", "x@evil.com"}},
		"cc":        {To: []string{"alice@example.com"}, Cc: []string{"x@evil.com"}},
		"bcc":       {To: []string{"alice@example.com"}, Bcc: []string{"x@evil.com"}},
		"subdomain": {To: []string{"x@mail.example.com"}},
		"too many": {To: []string{"1@example.com", "2@example.com", "3@example.com", "4@example.com", "5@example.com", "6@example.com",
			"7@example.com", "8@example.com", "9@example.com", "10@example.com", "11@example.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
			t.Setenv("GATE_TEST_PW", "") // a credential lookup would fail loudly
			out.Subject, out.Text = "s", "b"
			_, err := e.sess.Send(out)
			var de *gate.DeniedError
			if !errors.As(err, &de) {
				t.Fatalf("err = %v, want DeniedError", err)
			}
			if e.smtp.Connections() != 0 || e.commands() != "" {
				t.Errorf("smtp conns=%d imap=%q", e.smtp.Connections(), e.commands())
			}
			recs := e.records(t)
			if len(recs) != 1 || recs[0].Outcome != audit.OutcomeDenied || recs[0].Action != "send" {
				t.Fatalf("records = %+v", recs)
			}
		})
	}
}

func TestSendDenialNamesFirstRejectedAddress(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	_, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com", "first@evil.com", "second@evil.org"}, Subject: "s", Text: "b"})
	if err == nil || !strings.Contains(err.Error(), "first@evil.com") || strings.Contains(err.Error(), "second@evil.org") {
		t.Errorf("err = %v", err)
	}
}

func TestSendDisabledIsDenied(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, policy.Spec{Allow: []string{"Agent"}})
	_, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"})
	var de *gate.DeniedError
	if !errors.As(err, &de) || !strings.Contains(de.Reason, "not enabled") || e.smtp.Connections() != 0 {
		t.Errorf("err = %v, conns = %d", err, e.smtp.Connections())
	}
}

func TestSendRejectsHeaderInjectionAndBadInput(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	base := gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"}
	cases := map[string]func(o *gate.Outgoing){
		"crlf subject":    func(o *gate.Outgoing) { o.Subject = "hi\r\nBcc: x@evil.com" },
		"lf subject":      func(o *gate.Outgoing) { o.Subject = "hi\nBcc: x@evil.com" },
		"no subject":      func(o *gate.Outgoing) { o.Subject = "" },
		"path attachment": func(o *gate.Outgoing) { o.Attachments = []gate.Attachment{{Name: "../x", Data: []byte("x")}} },
		"crlf attachment": func(o *gate.Outgoing) { o.Attachments = []gate.Attachment{{Name: "a\r\nb", Data: []byte("x")}} },
		"empty":           func(o *gate.Outgoing) { o.Text = "" },
		"no recipients":   func(o *gate.Outgoing) { o.To = nil },
	}
	for name, mod := range cases {
		o := base
		mod(&o)
		_, err := e.sess.Send(o)
		var ue *gate.UsageError
		if !errors.As(err, &ue) {
			t.Errorf("%s: err = %v, want UsageError", name, err)
		}
	}
	if e.smtp.Connections() != 0 || len(e.records(t)) != 0 {
		t.Errorf("usage errors must not connect or be audited: conns=%d", e.smtp.Connections())
	}
	// A CRLF smuggled into an address is a policy denial, not a header.
	_, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com\r\nBcc: x@evil.com"}, Subject: "s", Text: "b"})
	var de *gate.DeniedError
	if !errors.As(err, &de) || e.smtp.Connections() != 0 {
		t.Errorf("crlf address: err = %v", err)
	}
}

func TestReplySetsThreadingHeadersAndDefaultSubject(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	res, err := e.sess.Send(gate.Outgoing{
		To: []string{"alice@example.com"}, Text: "thanks",
		Reply: &gate.ReplyRef{Mailbox: "Agent", UID: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := e.smtp.Deliveries()[0]
	h, _, _ := parseDelivery(t, d.Data)
	if subj, _ := h.Subject(); subj != "Re: Agent hello" {
		t.Errorf("subject = %q", subj)
	}
	irt, _ := h.MsgIDList("In-Reply-To")
	refs, _ := h.MsgIDList("References")
	if len(irt) != 1 || irt[0] != "agent-1@example.test" || len(refs) != 1 || refs[0] != "agent-1@example.test" {
		t.Errorf("in-reply-to=%v references=%v", irt, refs)
	}
	if len(d.To) != 1 || d.To[0] != "alice@example.com" {
		t.Errorf("a reply must not add recipients: %v", d.To)
	}
	recs := e.records(t)
	if len(recs) != 1 || recs[0].Mailbox != "Agent" || len(recs[0].UIDs) != 1 || recs[0].UIDs[0] != 1 || recs[0].Args["message_id"] != res.MessageID {
		t.Errorf("records = %+v", recs)
	}
	if !strings.Contains(e.commands(), "EXAMINE") || strings.Contains(e.commands(), "SELECT") {
		t.Errorf("reply must open the mailbox read-only:\n%s", e.commands())
	}
	if recs[0].Args["subject_sha256"] == "" {
		t.Error("defaulted subject must still be recorded as a hash")
	}
}

func TestReplyExtendsReferencesAndKeepsExplicitSubject(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	// Seed message 3 in INBOX already carries no References, so thread it by hand.
	c, err := e.srv.Client()
	if err != nil {
		t.Fatal(err)
	}
	raw := "Message-ID: <child@example.test>\r\nIn-Reply-To: <parent@example.test>\r\nReferences: <root@example.test> <parent@example.test>\r\nFrom: a@example.test\r\nSubject: Re: topic\r\n\r\nx\r\n"
	cmd := c.Append("INBOX", int64(len(raw)), nil)
	cmd.Write([]byte(raw))
	cmd.Close()
	data, err := cmd.Wait()
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sess.Send(gate.Outgoing{
		To: []string{"alice@example.com"}, Subject: "own subject", Text: "x",
		Reply: &gate.ReplyRef{Mailbox: "inbox", UID: uint32(data.UID)},
	}); err != nil {
		t.Fatal(err)
	}
	h, _, _ := parseDelivery(t, e.smtp.Deliveries()[0].Data)
	refs, _ := h.MsgIDList("References")
	if strings.Join(refs, " ") != "root@example.test parent@example.test child@example.test" {
		t.Errorf("references = %v", refs)
	}
	if subj, _ := h.Subject(); subj != "own subject" {
		t.Errorf("subject = %q", subj)
	}
}

func TestReplyToDeniedMailboxIsBlockedBeforeAnyConnection(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	_, err := e.sess.Send(gate.Outgoing{
		To: []string{"alice@example.com"}, Subject: "s", Text: "b",
		Reply: &gate.ReplyRef{Mailbox: "Private", UID: 1},
	})
	var de *gate.DeniedError
	if !errors.As(err, &de) || !strings.Contains(de.Reason, "reply-to") {
		t.Fatalf("err = %v", err)
	}
	if e.smtp.Connections() != 0 || e.commands() != "" {
		t.Errorf("smtp=%d imap=%q", e.smtp.Connections(), e.commands())
	}
	if recs := e.records(t); len(recs) != 1 || recs[0].Outcome != audit.OutcomeDenied || recs[0].Mailbox != "Private" {
		t.Errorf("records = %+v", recs)
	}
}

func TestReplyNeedsReadActionEnabled(t *testing.T) {
	spec := sendSpec
	spec.Actions = []string{"send"}
	e := setupSend(t, testserver.SMTPOptions{}, spec)
	_, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b", Reply: &gate.ReplyRef{Mailbox: "Agent", UID: 1}})
	var de *gate.DeniedError
	if !errors.As(err, &de) {
		t.Errorf("err = %v, want denied", err)
	}
}

func TestSendErrorsAreAuditedAndMissingReplyTargetSendsNothing(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	_, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b", Reply: &gate.ReplyRef{Mailbox: "Agent", UID: 999}})
	if err == nil || len(e.smtp.Deliveries()) != 0 {
		t.Fatalf("err = %v, deliveries = %d", err, len(e.smtp.Deliveries()))
	}
	rejecting := setupSend(t, testserver.SMTPOptions{RejectRcpt: map[string]bool{"alice@example.com": true}}, sendSpec)
	_, err = rejecting.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"})
	if err == nil {
		t.Fatal("send succeeded although the server rejected the recipient")
	}
	for _, env := range []*sendEnv{e, rejecting} {
		recs := env.records(t)
		if len(recs) != 1 || recs[0].Outcome != audit.OutcomeError {
			t.Errorf("records = %+v", recs)
		}
	}
}

func TestSendOverStartTLS(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{StartTLS: true}, sendSpec)
	if _, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"}); err != nil {
		t.Fatal(err)
	}
	if len(e.smtp.Deliveries()) != 1 {
		t.Error("message not delivered over STARTTLS")
	}
}

func TestSendRefusesUntrustedSMTPCertificate(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	pol := mustPolicy(t, sendSpec)
	log, _ := audit.Open(filepath.Join(t.TempDir(), "a.jsonl"))
	defer log.Close()
	acct := config.Account{
		Host: e.srv.Host, Port: e.srv.Port, Username: testserver.Username, Auth: config.AuthPassword, PasswordEnv: "GATE_TEST_PW",
		Policy: pol, SMTP: config.SMTP{Host: e.smtp.Host, Port: e.smtp.Port},
	}
	sess := gate.New("x", pol, log, gate.Dialer(acct), gate.SMTPOutbound(acct), nil)
	if _, err := sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"}); err == nil {
		t.Fatal("sent through a server whose certificate is not trusted")
	}
	if len(e.smtp.Deliveries()) != 0 {
		t.Error("delivered anyway")
	}
}

func TestSendWithBadCredentialsFails(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	t.Setenv("GATE_TEST_PW", "wrong")
	if _, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"}); err == nil || len(e.smtp.Deliveries()) != 0 {
		t.Errorf("err = %v", err)
	}
}
