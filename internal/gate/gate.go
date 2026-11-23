// Package gate is the single choke point between the CLI and the mail server.
// Every exported Session method checks policy, performs the action, and writes
// one audit record, in that order. Nothing else holds an IMAP or SMTP
// connection.
package gate

import (
	"fmt"
	"strings"

	"github.com/emersion/go-imap/v2/imapclient"

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
	client   *imapclient.Client
}

// New takes an already-open audit log: callers open it before anything can
// reach the network, and fail closed when they cannot. outbound is the zero
// value for a session that never sends.
func New(account string, pol policy.Policy, log *audit.Log, connect ConnectFunc, outbound Outbound) *Session {
	return &Session{account: account, policy: pol, log: log, connect: connect, outbound: outbound}
}

func (s *Session) Close() error {
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

// AuditError reports that the audit record could not be written. Results of
// the action are withheld. Performed is true when a server-side change had
// already happened.
type AuditError struct {
	Err       error
	Performed bool
}

func (e *AuditError) Error() string {
	if e.Performed {
		return fmt.Sprintf("action completed but could not be recorded: %v", e.Err)
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
	// recipients is every To, Cc and Bcc address of a send.
	recipients []string
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

// audited checks policy, then runs exec, then appends one record. It opens no
// connection itself: exec decides which servers it needs, so a denied attempt
// touches none of them.
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

	var execErr error
	rec.Count, execErr = exec()
	if execErr != nil {
		rec.Outcome, rec.Reason, rec.Count = audit.OutcomeError, clip(execErr.Error()), 0
	} else {
		rec.Outcome = audit.OutcomeOK
	}
	if _, err := s.log.Append(rec); err != nil {
		return &AuditError{Err: err, Performed: execErr == nil && policy.Actions[at.action].Write}
	}
	return execErr
}
