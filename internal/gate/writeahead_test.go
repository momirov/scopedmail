package gate_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/momirov/scopedmail/internal/agentfs"
	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/gate"
	"github.com/momirov/scopedmail/internal/policy"
	"github.com/momirov/scopedmail/internal/testserver"
)

// closedLog is a log every append fails on, the state a file size limit or a
// full disk leaves the gate in.
func closedLog(t *testing.T) *audit.Log {
	t.Helper()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	log.Close()
	return log
}

func TestSendThatCannotBeRecordedIsNeverSubmitted(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	sess := gate.New("test", e.acct.Policy, closedLog(t), gate.Dialer(e.acct), gate.SMTPOutbound(e.acct), nil)
	defer sess.Close()
	_, err := sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"})
	var ae *gate.AuditError
	if !errors.As(err, &ae) || ae.Performed {
		t.Fatalf("err = %v, want an AuditError for an action that did not run", err)
	}
	if n, c := len(e.smtp.Deliveries()), e.smtp.Connections(); n != 0 || c != 0 {
		t.Errorf("deliveries = %d, smtp connections = %d, want none", n, c)
	}
}

func TestWriteThatCannotBeRecordedNeverReachesTheServer(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions}, testserver.Options{})
	sess := gate.New("test", e.acct.Policy, closedLog(t), gate.Dialer(e.acct), gate.Outbound{}, nil)
	defer sess.Close()
	before := e.count(t, "Agent")
	e.srv.ResetCommands()
	var ae *gate.AuditError
	if err := sess.Delete("Agent", []uint32{1}); !errors.As(err, &ae) || ae.Performed {
		t.Fatalf("err = %v, want an AuditError for an action that did not run", err)
	}
	if cmds := e.commands(); cmds != "" {
		t.Errorf("an unrecorded delete reached the server:\n%s", cmds)
	}
	if after := e.count(t, "Agent"); after != before {
		t.Errorf("Agent holds %d messages, had %d", after, before)
	}
}

func TestWriteRecordsItsIntentBeforeItsOutcome(t *testing.T) {
	e := setupSend(t, testserver.SMTPOptions{}, sendSpec)
	res, err := e.sess.Send(gate.Outgoing{To: []string{"alice@example.com"}, Subject: "s", Text: "b"})
	if err != nil {
		t.Fatal(err)
	}
	recs := e.records(t)
	if len(recs) != 2 {
		t.Fatalf("records = %+v, want an intent and an outcome", recs)
	}
	intent, outcome := recs[0], recs[1]
	if intent.Outcome != audit.OutcomeStarted || intent.Args["to"] != "alice@example.com" || intent.Args["message_id"] != "" {
		t.Errorf("intent = %+v", intent)
	}
	if outcome.Outcome != audit.OutcomeOK || outcome.IntentSeq != intent.Seq || outcome.Args["message_id"] != res.MessageID {
		t.Errorf("outcome = %+v", outcome)
	}
	v, err := audit.Verify(e.log)
	if err != nil || len(v.Unfinished) != 0 {
		t.Errorf("verify = %+v, %v", v, err)
	}
}

func TestAttachmentIsRemovedWhenItsReadCannotBeRecorded(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	sess := gate.New("test", e.acct.Policy, closedLog(t), gate.Dialer(e.acct), gate.Outbound{}, agentfs.New(e.files))
	defer sess.Close()
	var ae *gate.AuditError
	if _, err := sess.Attachment("Agent", 2, "2", "report.txt"); !errors.As(err, &ae) {
		t.Fatalf("err = %v, want AuditError", err)
	}
	if _, err := os.Stat(filepath.Join(e.files, "report.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unrecorded attachment was left in files_dir: %v", err)
	}
}
