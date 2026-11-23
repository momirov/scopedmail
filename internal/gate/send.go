package gate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"

	"github.com/momirov/scopedmail/internal/policy"
)

// Send composes and submits one message. Policy sees every To, Cc and Bcc
// address, and the read policy sees the mailbox of a reply, before any server
// is contacted or any credential command runs. A denied send is audited with
// its recipients and nothing else. The log never holds message text.
func (s *Session) Send(out Outgoing) (*SendResult, error) {
	if err := out.validate(); err != nil {
		return nil, &UsageError{Msg: err.Error()}
	}
	rcpts := out.recipients()
	at := attempt{action: policy.Send, recipients: rcpts, args: out.auditArgs()}
	if r := out.Reply; r != nil {
		at.mailbox, at.uids = policy.Canonical(r.Mailbox), []uint32{r.UID}
	}
	var res *SendResult
	err := s.audited(at, func() (int, error) {
		var reply *replyContext
		if out.Reply != nil {
			c, err := s.conn()
			if err != nil {
				return 0, err
			}
			if reply, err = fetchReplyContext(c, at.mailbox, out.Reply.UID); err != nil {
				return 0, fmt.Errorf("reply-to: %w", err)
			}
		}
		raw, id, err := compose(s.outbound.From, out, reply, time.Now())
		if err != nil {
			return 0, err
		}
		at.args["message_id"], at.args["sha256"] = id, sha256Hex(raw)
		if reply != nil {
			at.args["subject_sha256"] = sha256Hex([]byte(replyOrGiven(out.Subject, reply)))
		}
		if len(raw) > MaxMessageBytes {
			return 0, fmt.Errorf("message is %d bytes, over the %d byte limit", len(raw), MaxMessageBytes)
		}
		if s.outbound.Send == nil {
			return 0, errors.New("sending is not configured for this account")
		}
		if err := s.outbound.Send(s.outbound.From, rcpts, raw); err != nil {
			return 0, err
		}
		res = &SendResult{MessageID: id, Recipients: rcpts}
		return len(rcpts), nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func replyOrGiven(subject string, reply *replyContext) string {
	if subject != "" {
		return subject
	}
	return replySubject(reply.Subject)
}

// fetchReplyContext reads only the headers a reply needs, with the same
// read-only EXAMINE and PEEK the read action uses.
func fetchReplyContext(c *imapclient.Client, mailbox string, uid uint32) (*replyContext, error) {
	if err := examine(c, mailbox); err != nil {
		return nil, err
	}
	refs := &imap.FetchItemBodySection{
		Specifier:    imap.PartSpecifierHeader,
		HeaderFields: []string{"References"},
		Peek:         true,
	}
	msg, err := fetchOne(c, imap.UIDSetNum(imap.UID(uid)), &imap.FetchOptions{UID: true, Envelope: true, BodySection: []*imap.FetchItemBodySection{refs}})
	if err != nil {
		return nil, err
	}
	if msg.Envelope == nil || msg.Envelope.MessageID == "" {
		return nil, errors.New("the original has no Message-ID to reply to")
	}
	rc := &replyContext{MessageID: msg.Envelope.MessageID, Subject: msg.Envelope.Subject, References: msg.Envelope.InReplyTo}
	if hdr, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(msg.FindBodySection(refs)))); err == nil {
		h := mail.Header{Header: message.Header{Header: hdr}}
		if ids, err := h.MsgIDList("References"); err == nil && len(ids) > 0 {
			rc.References = ids
		}
	}
	return rc, nil
}
