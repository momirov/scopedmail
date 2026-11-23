package gate

import (
	"errors"
	"fmt"
	"io"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/momirov/scopedmail/internal/policy"
	"github.com/momirov/scopedmail/internal/quote"
)

type MailboxInfo struct {
	Name     string `json:"name"`
	Messages uint32 `json:"messages"`
	Unseen   uint32 `json:"unseen"`
}

// Mailboxes lists only mailboxes the policy allows. Disallowed names are
// dropped before any further command, so neither the output nor the wire
// carries them past the LIST.
func (s *Session) Mailboxes() ([]MailboxInfo, error) {
	var out []MailboxInfo
	err := s.run(attempt{action: policy.Mailboxes}, func(c *imapclient.Client) (int, error) {
		listed, err := c.List("", "*", nil).Collect()
		if err != nil {
			return 0, err
		}
		for _, l := range listed {
			if !s.policy.MailboxAllowed(l.Mailbox) || hasAttr(l.Attrs, imap.MailboxAttrNoSelect) {
				continue
			}
			st, err := c.Status(l.Mailbox, &imap.StatusOptions{NumMessages: true, NumUnseen: true}).Wait()
			if err != nil {
				return 0, err
			}
			info := MailboxInfo{Name: l.Mailbox}
			if st.NumMessages != nil {
				info.Messages = *st.NumMessages
			}
			if st.NumUnseen != nil {
				info.Unseen = *st.NumUnseen
			}
			out = append(out, info)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return len(out), nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []MailboxInfo{}
	}
	return out, nil
}

func hasAttr(attrs []imap.MailboxAttr, want imap.MailboxAttr) bool {
	for _, a := range attrs {
		if strings.EqualFold(string(a), string(want)) {
			return true
		}
	}
	return false
}

type SeenFilter int

const (
	SeenAny SeenFilter = iota
	SeenOnly
	UnseenOnly
)

type SearchQuery struct {
	From, To, Subject, Body, Text string
	Since, Before                 time.Time
	Seen                          SeenFilter
	Flagged                       bool
	Limit                         int
}

func (q SearchQuery) args() map[string]string {
	a := map[string]string{}
	for k, v := range map[string]string{"from": q.From, "to": q.To, "subject": q.Subject, "body": q.Body, "text": q.Text} {
		if v != "" {
			a[k] = v
		}
	}
	const day = "2006-01-02"
	if !q.Since.IsZero() {
		a["since"] = q.Since.Format(day)
	}
	if !q.Before.IsZero() {
		a["before"] = q.Before.Format(day)
	}
	switch q.Seen {
	case SeenOnly:
		a["seen"] = "true"
	case UnseenOnly:
		a["unseen"] = "true"
	}
	if q.Flagged {
		a["flagged"] = "true"
	}
	a["limit"] = strconv.Itoa(q.Limit)
	return a
}

func (q SearchQuery) criteria() *imap.SearchCriteria {
	c := &imap.SearchCriteria{Since: q.Since, Before: q.Before}
	for k, v := range map[string]string{"From": q.From, "To": q.To, "Subject": q.Subject} {
		if v != "" {
			c.Header = append(c.Header, imap.SearchCriteriaHeaderField{Key: k, Value: v})
		}
	}
	if q.Body != "" {
		c.Body = []string{q.Body}
	}
	if q.Text != "" {
		c.Text = []string{q.Text}
	}
	switch q.Seen {
	case SeenOnly:
		c.Flag = append(c.Flag, imap.FlagSeen)
	case UnseenOnly:
		c.NotFlag = append(c.NotFlag, imap.FlagSeen)
	}
	if q.Flagged {
		c.Flag = append(c.Flag, imap.FlagFlagged)
	}
	return c
}

type Summary struct {
	UID       uint32   `json:"uid"`
	MessageID string   `json:"message_id"`
	Date      string   `json:"date"`
	From      []string `json:"from"`
	To        []string `json:"to"`
	Cc        []string `json:"cc"`
	Subject   string   `json:"subject"`
	Flags     []string `json:"flags"`
	Size      int64    `json:"size"`
}

var summaryFetch = &imap.FetchOptions{UID: true, Envelope: true, Flags: true, RFC822Size: true, InternalDate: true}

func summarize(m *imapclient.FetchMessageBuffer) Summary {
	s := Summary{UID: uint32(m.UID), Size: m.RFC822Size, From: []string{}, To: []string{}, Cc: []string{}, Flags: []string{}}
	date := m.InternalDate
	if e := m.Envelope; e != nil {
		s.MessageID, s.Subject = e.MessageID, e.Subject
		s.From, s.To, s.Cc = addrs(e.From), addrs(e.To), addrs(e.Cc)
		if !e.Date.IsZero() {
			date = e.Date
		}
	}
	if !date.IsZero() {
		s.Date = date.UTC().Format(time.RFC3339)
	}
	for _, f := range m.Flags {
		s.Flags = append(s.Flags, string(f))
	}
	return s
}

func addrs(in []imap.Address) []string {
	out := []string{}
	for _, a := range in {
		addr := a.Addr()
		if addr == "" {
			continue
		}
		if a.Name == "" {
			out = append(out, addr)
		} else {
			out = append(out, (&mail.Address{Name: a.Name, Address: addr}).String())
		}
	}
	return out
}

func examine(c *imapclient.Client, mailbox string) error {
	_, err := c.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	return err
}

func selectRW(c *imapclient.Client, mailbox string) error {
	_, err := c.Select(mailbox, nil).Wait()
	return err
}

// Search returns the newest Limit matches, newest first.
func (s *Session) Search(mailbox string, q SearchQuery) ([]Summary, error) {
	mailbox = policy.Canonical(mailbox)
	var out []Summary
	err := s.run(attempt{action: policy.Search, mailbox: mailbox, args: q.args()}, func(c *imapclient.Client) (int, error) {
		if err := examine(c, mailbox); err != nil {
			return 0, err
		}
		found, err := c.UIDSearch(q.criteria(), nil).Wait()
		if err != nil {
			return 0, err
		}
		uids := found.AllUIDs()
		sort.Slice(uids, func(i, j int) bool { return uids[i] > uids[j] })
		if q.Limit > 0 && len(uids) > q.Limit {
			uids = uids[:q.Limit]
		}
		if len(uids) == 0 {
			return 0, nil
		}
		msgs, err := c.Fetch(imap.UIDSetNum(uids...), summaryFetch).Collect()
		if err != nil {
			return 0, err
		}
		for _, m := range msgs {
			out = append(out, summarize(m))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].UID > out[j].UID })
		return len(out), nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Summary{}
	}
	return out, nil
}

type AttachmentInfo struct {
	Part     string `json:"part"`
	Filename string `json:"filename,omitempty"`
	Type     string `json:"type"`
	Size     uint32 `json:"size"`
}

type ReadOptions struct {
	Raw  bool
	HTML bool
	// KeepQuotes returns the bodies as sent, with the quoted reply history.
	KeepQuotes bool
}

// QuotesRemoved tells the reader how much quoted history Read left out of the
// text and html fields together. Bytes and lines count the original content.
type QuotesRemoved struct {
	Bytes int `json:"bytes"`
	Lines int `json:"lines"`
}

type Message struct {
	Summary
	InReplyTo []string `json:"in_reply_to,omitempty"`
	Text      string   `json:"text"`
	HTML      string   `json:"html,omitempty"`
	// Raw is set whenever the read asked for it, even when empty, so a missing
	// key never stands for a message that has a source.
	Raw         *string          `json:"raw,omitempty"`
	Attachments []AttachmentInfo `json:"attachments"`
	// QuotesRemoved is set only when Read removed something.
	QuotesRemoved *QuotesRemoved `json:"quotes_removed,omitempty"`
}

var structureFetch = &imap.FetchOptions{
	UID: true, Envelope: true, Flags: true, RFC822Size: true, InternalDate: true,
	BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
}

func peekSection(path []int) *imap.FetchItemBodySection {
	return &imap.FetchItemBodySection{Part: path, Peek: true}
}

// Read fetches with BODY.PEEK on an EXAMINEd mailbox, so reading never sets
// \Seen.
func (s *Session) Read(mailbox string, uid uint32, opt ReadOptions) (*Message, error) {
	mailbox = policy.Canonical(mailbox)
	args := map[string]string{}
	if opt.Raw {
		args["raw"] = "true"
	}
	if opt.HTML {
		args["html"] = "true"
	}
	if opt.KeepQuotes {
		args["keep_quotes"] = "true"
	}
	var out *Message
	err := s.run(attempt{action: policy.Read, mailbox: mailbox, uids: []uint32{uid}, args: args}, func(c *imapclient.Client) (int, error) {
		if err := examine(c, mailbox); err != nil {
			return 0, err
		}
		set := imap.UIDSetNum(imap.UID(uid))
		msg, err := fetchOne(c, set, structureFetch)
		if err != nil {
			return 0, err
		}
		m := &Message{Summary: summarize(msg), Attachments: []AttachmentInfo{}}
		if msg.Envelope != nil {
			m.InReplyTo = msg.Envelope.InReplyTo
		}
		if opt.Raw {
			full := &imap.FetchItemBodySection{Peek: true}
			raw, err := fetchOne(c, set, &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{full}})
			if err != nil {
				return 0, err
			}
			src := raw.FindBodySection(full)
			if len(src) == 0 && m.Size > 0 {
				return 0, fmt.Errorf("server returned no source for the %d byte message", m.Size)
			}
			text := strings.ToValidUTF8(string(src), "�")
			m.Raw = &text
			out = m
			return 1, nil
		}
		if msg.BodyStructure == nil {
			return 0, errors.New("server returned no body structure")
		}
		var textParts, htmlParts []leaf
		for _, l := range leaves(msg.BodyStructure) {
			switch {
			case l.isAttachment():
				m.Attachments = append(m.Attachments, AttachmentInfo{Part: l.partID(), Filename: l.bs.Filename(), Type: l.mediaType(), Size: l.bs.Size})
			case l.mediaType() == "text/plain":
				textParts = append(textParts, l)
			case l.mediaType() == "text/html":
				htmlParts = append(htmlParts, l)
			}
		}
		wantHTML := opt.HTML || len(textParts) == 0
		fetch := textParts
		if wantHTML {
			fetch = append(append([]leaf(nil), textParts...), htmlParts...)
		}
		if len(fetch) > 0 {
			sections := make([]*imap.FetchItemBodySection, len(fetch))
			for i, l := range fetch {
				sections[i] = peekSection(l.path)
			}
			body, err := fetchOne(c, set, &imap.FetchOptions{UID: true, BodySection: sections})
			if err != nil {
				return 0, err
			}
			// A forward is new content, and Outlook marks a reply and a
			// forward the same way, so a forward subject is never stripped.
			strip := !opt.KeepQuotes && !quote.IsForwardSubject(m.Subject)
			var texts, htmls []string
			var removed QuotesRemoved
			for i, l := range fetch {
				t := decodeText(body.FindBodySection(sections[i]), l)
				isHTML := l.mediaType() == "text/html"
				if strip {
					stripper := quote.StripText
					if isHTML {
						stripper = quote.StripHTML
					}
					res := stripper(t)
					t = res.Text
					removed.Bytes += res.RemovedBytes
					removed.Lines += res.RemovedLines
				}
				if isHTML {
					htmls = append(htmls, t)
				} else {
					texts = append(texts, t)
				}
			}
			m.Text, m.HTML = strings.Join(texts, "\n"), strings.Join(htmls, "\n")
			if removed.Bytes > 0 {
				m.QuotesRemoved = &removed
			}
		}
		out = m
		return 1, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func fetchOne(c *imapclient.Client, set imap.UIDSet, opts *imap.FetchOptions) (*imapclient.FetchMessageBuffer, error) {
	msgs, err := c.Fetch(set, opts).Collect()
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errors.New("no such message")
	}
	return msgs[0], nil
}

type AttachmentResult struct {
	Part  string `json:"part"`
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// Attachment streams one part to a new file at out, inside files_dir. It
// refuses to overwrite: an agent that controls the path must not be able to
// clobber existing files. The result's path is where the file landed.
func (s *Session) Attachment(mailbox string, uid uint32, part string, out string) (*AttachmentResult, error) {
	mailbox = policy.Canonical(mailbox)
	path, perr := parsePartID(part)
	if perr != nil {
		return nil, &UsageError{Msg: perr.Error()}
	}
	var res *AttachmentResult
	err := s.run(attempt{action: policy.Attachment, mailbox: mailbox, uids: []uint32{uid}, file: out, args: map[string]string{"part": part, "out": out}}, func(c *imapclient.Client) (int, error) {
		if err := examine(c, mailbox); err != nil {
			return 0, err
		}
		set := imap.UIDSetNum(imap.UID(uid))
		msg, err := fetchOne(c, set, &imap.FetchOptions{UID: true, BodyStructure: &imap.FetchItemBodyStructure{Extended: true}})
		if err != nil {
			return 0, err
		}
		if msg.BodyStructure == nil {
			return 0, errors.New("server returned no body structure")
		}
		var target *leaf
		for _, l := range leaves(msg.BodyStructure) {
			if partID(l.path) == partID(path) {
				l := l
				target = &l
			}
		}
		if target == nil {
			return 0, fmt.Errorf("message has no part %s", part)
		}
		n, where, err := s.streamPart(c, set, path, target.bs.Encoding, out)
		if err != nil {
			return 0, err
		}
		res = &AttachmentResult{Part: part, Path: where, Bytes: n}
		return 1, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Session) streamPart(c *imapclient.Client, set imap.UIDSet, path []int, encoding, out string) (n int64, where string, err error) {
	f, where, err := s.files.Create(out)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			s.files.Remove(out)
		}
	}()
	cmd := c.Fetch(set, &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{peekSection(path)}})
	defer cmd.Close()
	got := false
	for msg := cmd.Next(); msg != nil; msg = cmd.Next() {
		for item := msg.Next(); item != nil; item = msg.Next() {
			sec, ok := item.(imapclient.FetchItemDataBodySection)
			if !ok || sec.Literal == nil {
				continue
			}
			got = true
			if n, err = io.Copy(f, decodeBody(sec.Literal, encoding)); err != nil {
				return n, where, err
			}
		}
	}
	if err := cmd.Close(); err != nil {
		return n, where, err
	}
	if !got {
		return 0, where, errors.New("server returned no data for the part")
	}
	return n, where, nil
}

var systemFlags = map[string]imap.Flag{
	"seen": imap.FlagSeen, "flagged": imap.FlagFlagged, "answered": imap.FlagAnswered, "draft": imap.FlagDraft,
}

// ParseFlag maps a CLI flag name to an IMAP flag. \Deleted is refused: only
// the delete action may mark mail for removal.
func ParseFlag(name string) (imap.Flag, error) {
	if f, ok := systemFlags[strings.ToLower(name)]; ok {
		return f, nil
	}
	switch strings.ToLower(name) {
	case "", "deleted", "recent":
		return "", fmt.Errorf("unsupported flag %q", name)
	}
	if strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("unsupported flag %q", name)
	}
	for _, r := range name {
		ok := r == '$' || r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !ok {
			return "", fmt.Errorf("invalid keyword %q", name)
		}
	}
	return imap.Flag(name), nil
}

func parseFlags(names []string) ([]imap.Flag, error) {
	var out []imap.Flag
	for _, n := range names {
		f, err := ParseFlag(n)
		if err != nil {
			return nil, &UsageError{Msg: err.Error()}
		}
		out = append(out, f)
	}
	return out, nil
}

func uidSet(uids []uint32) imap.UIDSet {
	var set imap.UIDSet
	for _, u := range uids {
		set.AddNum(imap.UID(u))
	}
	return set
}

func (s *Session) Flag(mailbox string, uids []uint32, add, remove []string) error {
	mailbox = policy.Canonical(mailbox)
	addF, err := parseFlags(add)
	if err != nil {
		return err
	}
	remF, err := parseFlags(remove)
	if err != nil {
		return err
	}
	args := map[string]string{}
	if len(add) > 0 {
		args["add"] = strings.Join(add, ",")
	}
	if len(remove) > 0 {
		args["remove"] = strings.Join(remove, ",")
	}
	return s.run(attempt{action: policy.Flag, mailbox: mailbox, uids: uids, args: args}, func(c *imapclient.Client) (int, error) {
		if err := selectRW(c, mailbox); err != nil {
			return 0, err
		}
		set := uidSet(uids)
		for _, op := range []struct {
			op    imap.StoreFlagsOp
			flags []imap.Flag
		}{{imap.StoreFlagsAdd, addF}, {imap.StoreFlagsDel, remF}} {
			if len(op.flags) == 0 {
				continue
			}
			if err := c.Store(set, &imap.StoreFlags{Op: op.op, Silent: true, Flags: op.flags}, nil).Close(); err != nil {
				return 0, err
			}
		}
		return len(uids), nil
	})
}

// Copy returns the destination UIDs when the server reports them.
func (s *Session) Copy(mailbox, target string, uids []uint32) ([]uint32, error) {
	mailbox, target = policy.Canonical(mailbox), policy.Canonical(target)
	var dest []uint32
	err := s.run(attempt{action: policy.Copy, mailbox: mailbox, target: target, uids: uids}, func(c *imapclient.Client) (int, error) {
		if err := examine(c, mailbox); err != nil {
			return 0, err
		}
		data, err := c.Copy(uidSet(uids), target).Wait()
		if err != nil {
			return 0, err
		}
		dest = numsOf(data.DestUIDs)
		return len(uids), nil
	})
	return dest, err
}

func numsOf(set imap.UIDSet) []uint32 {
	nums, ok := set.Nums()
	if !ok {
		return nil
	}
	out := make([]uint32, len(nums))
	for i, n := range nums {
		out[i] = uint32(n)
	}
	return out
}

// Move uses MOVE when the server has it. Otherwise it copies, checks that the
// copy succeeded, and only then expunges exactly the moved UIDs. It does not
// use imapclient's own fallback, which pipelines COPY and EXPUNGE without
// waiting and falls back to an EXPUNGE that removes every \Deleted message.
func (s *Session) Move(mailbox, target string, uids []uint32) ([]uint32, error) {
	mailbox, target = policy.Canonical(mailbox), policy.Canonical(target)
	var dest []uint32
	err := s.run(attempt{action: policy.Move, mailbox: mailbox, target: target, uids: uids}, func(c *imapclient.Client) (int, error) {
		if err := selectRW(c, mailbox); err != nil {
			return 0, err
		}
		var err error
		if dest, err = moveTo(c, uidSet(uids), target); err != nil {
			return 0, err
		}
		return len(uids), nil
	})
	return dest, err
}

func moveTo(c *imapclient.Client, set imap.UIDSet, target string) ([]uint32, error) {
	if c.Caps().Has(imap.CapMove) {
		data, err := c.Move(set, target).Wait()
		if err != nil {
			return nil, err
		}
		if d, ok := data.DestUIDs.(imap.UIDSet); ok {
			return numsOf(d), nil
		}
		return nil, nil
	}
	if !c.Caps().Has(imap.CapUIDPlus) {
		return nil, errors.New("server supports neither MOVE nor UIDPLUS; refusing a move that could expunge other messages")
	}
	data, err := c.Copy(set, target).Wait()
	if err != nil {
		return nil, err
	}
	if err := expungeUIDs(c, set); err != nil {
		return nil, err
	}
	return numsOf(data.DestUIDs), nil
}

// expungeUIDs removes exactly set. A bare EXPUNGE would also remove unrelated
// messages another client had flagged \Deleted, so UIDPLUS is required.
func expungeUIDs(c *imapclient.Client, set imap.UIDSet) error {
	if !c.Caps().Has(imap.CapUIDPlus) {
		return errors.New("server lacks UIDPLUS; refusing to expunge without UID EXPUNGE")
	}
	if err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		return err
	}
	return c.UIDExpunge(set).Close()
}

// Delete moves to the configured trash, or removes the UIDs outright when none
// is configured. The trash sink is operator-chosen and skips the allowlist.
func (s *Session) Delete(mailbox string, uids []uint32) error {
	mailbox = policy.Canonical(mailbox)
	trash := s.policy.Trash()
	args := map[string]string{}
	if trash != "" {
		args["trash"] = trash
	}
	return s.run(attempt{action: policy.Delete, mailbox: mailbox, uids: uids, args: args}, func(c *imapclient.Client) (int, error) {
		if err := selectRW(c, mailbox); err != nil {
			return 0, err
		}
		set := uidSet(uids)
		var err error
		if trash != "" {
			_, err = moveTo(c, set, trash)
		} else {
			err = expungeUIDs(c, set)
		}
		if err != nil {
			return 0, err
		}
		return len(uids), nil
	})
}

// Append uploads size bytes from r. The reader is untouched when policy denies.
func (s *Session) Append(mailbox string, r io.Reader, size int64, flags []string, source string) (uint32, error) {
	mailbox = policy.Canonical(mailbox)
	fl, err := parseFlags(flags)
	if err != nil {
		return 0, err
	}
	args := map[string]string{"bytes": strconv.FormatInt(size, 10)}
	if len(flags) > 0 {
		args["flags"] = strings.Join(flags, ",")
	}
	if source != "" {
		args["file"] = source
	}
	var uid uint32
	err = s.run(attempt{action: policy.Append, mailbox: mailbox, args: args}, func(c *imapclient.Client) (int, error) {
		cmd := c.Append(mailbox, size, &imap.AppendOptions{Flags: fl})
		n, werr := io.Copy(cmd, io.LimitReader(r, size))
		cerr := cmd.Close()
		data, err := cmd.Wait()
		switch {
		case werr != nil:
			return 0, werr
		case n != size:
			return 0, fmt.Errorf("read %d bytes, expected %d", n, size)
		case cerr != nil:
			return 0, cerr
		case err != nil:
			return 0, err
		}
		uid = uint32(data.UID)
		return 1, nil
	})
	return uid, err
}

func (s *Session) CreateMailbox(name string) error {
	name = policy.Canonical(name)
	return s.run(attempt{action: policy.CreateMailbox, mailbox: name}, func(c *imapclient.Client) (int, error) {
		return 1, c.Create(name, nil).Wait()
	})
}
