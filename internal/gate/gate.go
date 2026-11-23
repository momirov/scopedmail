// Package gate is the single choke point between the CLI and the mail server.
// Every exported Session method checks policy, performs the action, and writes
// one audit record, in that order. Nothing else holds an IMAP connection.
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
	account string
	policy  policy.Policy
	log     *audit.Log
	connect ConnectFunc
	client  *imapclient.Client
}

// New takes an already-open audit log: callers open it before anything can
// reach the network, and fail closed when they cannot.
func New(account string, pol policy.Policy, log *audit.Log, connect ConnectFunc) *Session {
	return &Session{account: account, policy: pol, log: log, connect: connect}
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
	action  policy.Action
	mailbox string
	target  string
	uids    []uint32
	args    map[string]string
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

// run is the choke point. exec returns how many results it produced. The
// caller reads its results from variables exec closed over, and must discard
// them unless run returns nil, so output never outruns its audit record.
func (s *Session) run(at attempt, exec func(c *imapclient.Client) (int, error)) error {
	rec := audit.Record{
		Account: s.account,
		Action:  string(at.action),
		Mailbox: clip(at.mailbox),
		Target:  clip(at.target),
		UIDs:    at.uids,
		Args:    at.args,
	}
	if d := s.policy.Check(at.action, at.mailbox, at.target); !d.Allowed {
		rec.Outcome, rec.Reason = audit.OutcomeDenied, clip(d.Reason)
		if _, err := s.log.Append(rec); err != nil {
			return &AuditError{Err: err}
		}
		return &DeniedError{Action: at.action, Reason: d.Reason}
	}

	var execErr error
	c, err := s.conn()
	if err != nil {
		execErr = err
	} else {
		rec.Count, execErr = exec(c)
	}
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
