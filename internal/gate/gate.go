// Package gate is the single choke point between the CLI and the mail server.
// Every exported Session method checks policy, records a write before it
// starts, performs the action, and records the outcome, in that order.
// Nothing else holds an IMAP or SMTP connection.
package gate

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/momirov/scopedmail/internal/agentfs"
	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/policy"
)

// ConnectFunc dials and authenticates. The gate calls it lazily, so a denied
// action never opens a connection or fetches credentials.
type ConnectFunc func() (*imapclient.Client, error)

type Session struct {
	account  string
	policy   policy.Policy
	log      *audit.Log
	connect  ConnectFunc
	outbound Outbound
	files    *agentfs.Dir
	client   *imapclient.Client
}

// New takes an already-open audit log: callers open it before anything can
// reach the network, and fail closed when they cannot. outbound is the zero
// value for a session that never sends. files is the one place agent-supplied
// paths resolve; nil means file paths are off.
func New(account string, pol policy.Policy, log *audit.Log, connect ConnectFunc, outbound Outbound, files *agentfs.Dir) *Session {
	if files == nil {
		files = agentfs.New("")
	}
	return &Session{account: account, policy: pol, log: log, connect: connect, outbound: outbound, files: files}
}

func (s *Session) Close() error {
	s.files.Close()
	if s.client == nil {
		return nil
	}
	c := s.client
	s.client = nil
	_ = c.Logout().Wait()
	return c.Close()
}

// DeniedError reports a policy refusal. The denial was recorded in the audit
// log and no IMAP command was sent for the action.
type DeniedError struct {
	Action policy.Action
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("denied: %s: %s", e.Action, e.Reason)
}

// UsageError reports arguments the gate cannot act on. It is not an attempted
// action, so it is not audited.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// AuditError reports that an audit record could not be written. Results of
// the action are withheld. Performed is true when a server-side change had
// already happened: its intent is in the log, and its outcome is not.
type AuditError struct {
	Err       error
	Performed bool
}

func (e *AuditError) Error() string {
	if e.Performed {
		return fmt.Sprintf("action completed but its outcome could not be recorded, so the log shows it unfinished: %v", e.Err)
	}
	return e.Err.Error()
}

func (e *AuditError) Unwrap() error { return e.Err }

type attempt struct {
	action policy.Action
	// mailbox and uids name the message an action reads or changes. A send
	// sets them to the message it replies to.
	mailbox string
	target  string
	uids    []uint32
	// file is a path the action will create, checked before any connection.
	file string
	// recipients is every To, Cc and Bcc address of a send.
	recipients []string
	// keywords are the flags other than the system ones that flag or append
	// would set or clear.
	keywords []string
	// args is recorded as given. An action may add entries while it runs, for
	// facts only known then, and run records the map after exec returns.
	args map[string]string
}

func (s *Session) conn() (*imapclient.Client, error) {
	if s.client != nil {
		return s.client, nil
	}
	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	s.client = c
	return c, nil
}

const maxReason = 500

func clip(s string) string {
	if len(s) > maxReason {
		return strings.ToValidUTF8(s[:maxReason], "") + "..."
	}
	return s
}

// decide is the one policy question for an attempt. A send is judged by its
// recipients, and by the read policy on the message it replies to.
func (s *Session) decide(at attempt) policy.Decision {
	d := s.decideAction(at)
	if d.Allowed {
		d = s.policy.CheckKeywords(at.keywords)
	}
	if d.Allowed && at.file != "" {
		if err := s.files.Check(at.file); err != nil {
			return policy.Decision{Reason: err.Error()}
		}
	}
	return d
}

func (s *Session) decideAction(at attempt) policy.Decision {
	if !policy.Actions[at.action].Recipients {
		return s.policy.Check(at.action, at.mailbox, at.target)
	}
	if d := s.policy.CheckSend(at.recipients); !d.Allowed || at.mailbox == "" {
		return d
	}
	d := s.policy.Check(policy.Read, at.mailbox, "")
	if !d.Allowed {
		d.Reason = "reply-to: " + d.Reason
	}
	return d
}

// run is the choke point for actions on the IMAP server. exec returns how many
// results it produced. The caller reads its results from variables exec
// closed over, and must discard them unless run returns nil, so output never
// outruns its audit record.
func (s *Session) run(at attempt, exec func(c *imapclient.Client) (int, error)) error {
	return s.audited(at, func() (int, error) {
		c, err := s.conn()
		if err != nil {
			return 0, err
		}
		return exec(c)
	})
}

// audited checks policy, runs exec, and records the outcome. It opens no
// connection itself: exec decides which servers it needs, so a denied attempt
// touches none of them. A write first appends a durable intent, so a failed
// append, a kill or a crash can never leave a change on the server with
// nothing in the log. A read appends only its outcome; its results stay
// withheld unless that append succeeds.
func (s *Session) audited(at attempt, exec func() (int, error)) error {
	rec := audit.Record{
		Account: s.account,
		Action:  string(at.action),
		Mailbox: clip(at.mailbox),
		Target:  clip(at.target),
		UIDs:    at.uids,
		Args:    at.args,
	}
	if d := s.decide(at); !d.Allowed {
		rec.Outcome, rec.Reason = audit.OutcomeDenied, clip(d.Reason)
		if _, err := s.log.Append(rec); err != nil {
			return &AuditError{Err: err}
		}
		return &DeniedError{Action: at.action, Reason: d.Reason}
	}
	write := policy.Actions[at.action].Write
	if write {
		intent := rec
		intent.Args, intent.Outcome = maps.Clone(at.args), audit.OutcomeStarted
		stored, err := s.log.Append(intent)
		if err != nil {
			return &AuditError{Err: err}
		}
		rec.IntentSeq = stored.Seq
	}

	var execErr error
	rec.Count, execErr = exec()
	var badPath *agentfs.Denied
	if errors.As(execErr, &badPath) {
		execErr = &DeniedError{Action: at.action, Reason: badPath.Error()}
	}
	var denied *DeniedError
	switch {
	case errors.As(execErr, &denied):
		rec.Outcome, rec.Reason, rec.Count = audit.OutcomeDenied, clip(denied.Reason), 0
	case execErr != nil:
		rec.Outcome, rec.Reason, rec.Count = audit.OutcomeError, clip(execErr.Error()), 0
	default:
		rec.Outcome = audit.OutcomeOK
	}
	if _, err := s.log.Append(rec); err != nil {
		if execErr == nil && at.file != "" {
			s.files.Remove(at.file)
		}
		return &AuditError{Err: err, Performed: execErr == nil && write}
	}
	return execErr
}

// OpenFile opens a file the agent named, for action, through files_dir. A path
// the agent may not use is recorded as a denial before the error returns, so
// the log shows the attempt even though no action ran. The caller closes the
// file.
func (s *Session) OpenFile(action policy.Action, path string) (*os.File, os.FileInfo, error) {
	f, info, err := s.files.Open(path)
	var badPath *agentfs.Denied
	if !errors.As(err, &badPath) {
		return f, info, err
	}
	rec := audit.Record{
		Account: s.account,
		Action:  string(action),
		Args:    map[string]string{"file": clip(path)},
		Outcome: audit.OutcomeDenied,
		Reason:  clip(badPath.Error()),
	}
	if _, aerr := s.log.Append(rec); aerr != nil {
		return nil, nil, &AuditError{Err: aerr}
	}
	return nil, nil, &DeniedError{Action: action, Reason: badPath.Error()}
}
