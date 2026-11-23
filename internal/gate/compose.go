package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-message/mail"
)

const (
	// MaxMessageBytes is Gmail's limit on a composed message.
	MaxMessageBytes = 25 << 20

	maxSubjectBytes = 998
	maxAddresses    = 200
	maxReferences   = 10
)

type Attachment struct {
	Name string
	Data []byte
}

// ReplyRef names the message a send answers. The gate reads it under the read
// policy and takes its Message-ID, References and subject from the server.
type ReplyRef struct {
	Mailbox string
	UID     uint32
}

// Outgoing is everything an agent controls about a message. From is not here:
// it is always the account's own address, and no header can be set freely.
type Outgoing struct {
	// To, Cc and Bcc are bare addresses. Display names are not supported.
	To, Cc, Bcc []string
	// Subject may be empty only when Reply is set, which defaults it to
	// "Re: <original subject>".
	Subject     string
	Text        string
	HTML        string
	Attachments []Attachment
	Reply       *ReplyRef
}

type SendResult struct {
	MessageID  string   `json:"message_id"`
	Recipients []string `json:"recipients"`
}

// recipients returns every address once, in To, Cc, Bcc order. Case differences
// do not make two addresses distinct.
func (o Outgoing) recipients() []string {
	var out []string
	seen := map[string]bool{}
	for _, list := range [][]string{o.To, o.Cc, o.Bcc} {
		for _, a := range list {
			if k := strings.ToLower(a); !seen[k] {
				seen[k] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// validate rejects what cannot become a well-formed message. Recipient
// addresses are not judged here: that is policy's call, and a bad one is a
// denial.
func (o Outgoing) validate() error {
	if n := len(o.To) + len(o.Cc) + len(o.Bcc); n == 0 {
		return fmt.Errorf("at least one recipient is required")
	} else if n > maxAddresses {
		return fmt.Errorf("more than %d recipient addresses", maxAddresses)
	}
	if o.Subject == "" && o.Reply == nil {
		return fmt.Errorf("a subject is required unless replying")
	}
	if err := noControl("subject", o.Subject); err != nil {
		return err
	}
	if len(o.Subject) > maxSubjectBytes {
		return fmt.Errorf("subject is longer than %d bytes", maxSubjectBytes)
	}
	for _, body := range []struct{ name, s string }{{"body", o.Text}, {"html", o.HTML}} {
		if !utf8.ValidString(body.s) || strings.ContainsRune(body.s, 0) {
			return fmt.Errorf("%s is not valid UTF-8 text", body.name)
		}
	}
	if o.Text == "" && o.HTML == "" && len(o.Attachments) == 0 {
		return fmt.Errorf("the message has no content")
	}
	for _, a := range o.Attachments {
		if a.Name == "" || len(a.Name) > 255 || a.Name == "." || a.Name == ".." || strings.ContainsAny(a.Name, `/\`) {
			return fmt.Errorf("attachment name %q must be a plain file name", a.Name)
		}
		if err := noControl("attachment name", a.Name); err != nil {
			return err
		}
	}
	if r := o.Reply; r != nil && (r.Mailbox == "" || r.UID == 0) {
		return fmt.Errorf("a reply needs a mailbox and a UID")
	}
	return nil
}

func noControl(what, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", what)
		}
	}
	return nil
}

// replyContext is what a reply takes from the original message. Every field
// came from an untrusted sender, so compose treats it as data.
type replyContext struct {
	MessageID  string
	References []string
	Subject    string
}

// compose builds the message the agent is allowed to send. Bcc addresses stay
// out of the headers: they exist only in the SMTP envelope.
func compose(from string, o Outgoing, reply *replyContext, now time.Time) (raw []byte, messageID string, err error) {
	subject := o.Subject
	var h mail.Header
	if reply != nil {
		if subject == "" {
			subject = replySubject(reply.Subject)
		}
		refs := append(append([]string(nil), reply.References...), reply.MessageID)
		if len(refs) > maxReferences {
			refs = refs[len(refs)-maxReferences:]
		}
		h.SetMsgIDList("In-Reply-To", []string{reply.MessageID})
		h.SetMsgIDList("References", refs)
	}
	h.SetDate(now)
	h.SetAddressList("From", []*mail.Address{{Address: from}})
	h.SetAddressList("To", addressList(o.To))
	if len(o.Cc) > 0 {
		h.SetAddressList("Cc", addressList(o.Cc))
	}
	h.SetSubject(subject)
	_, domain, _ := strings.Cut(from, "@")
	if err := h.GenerateMessageIDWithHostname(domain); err != nil {
		return nil, "", err
	}
	if messageID, err = h.MessageID(); err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	w, err := mail.CreateWriter(&buf, h)
	if err != nil {
		return nil, "", err
	}
	if err := writeBody(w, o); err != nil {
		return nil, "", err
	}
	for _, a := range o.Attachments {
		var ah mail.AttachmentHeader
		ah.SetContentType(attachmentType(a.Name), nil)
		ah.SetFilename(a.Name)
		aw, err := w.CreateAttachment(ah)
		if err != nil {
			return nil, "", err
		}
		if err := writeAll(aw, a.Data); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), messageID, nil
}

func writeAll(w io.WriteCloser, data []byte) error {
	if _, err := w.Write(data); err != nil {
		return err
	}
	return w.Close()
}

// writeBody writes the text part, and the HTML alternative after it when there
// is one.
func writeBody(w *mail.Writer, o Outgoing) error {
	header := func(mediaType string) mail.InlineHeader {
		var ih mail.InlineHeader
		ih.SetContentType(mediaType, map[string]string{"charset": "utf-8"})
		return ih
	}
	if o.HTML == "" {
		if o.Text == "" {
			return nil
		}
		pw, err := w.CreateSingleInline(header("text/plain"))
		if err != nil {
			return err
		}
		return writeAll(pw, []byte(o.Text))
	}
	iw, err := w.CreateInline()
	if err != nil {
		return err
	}
	for _, p := range []struct{ mediaType, body string }{{"text/plain", o.Text}, {"text/html", o.HTML}} {
		if p.body == "" {
			continue
		}
		pw, err := iw.CreatePart(header(p.mediaType))
		if err != nil {
			return err
		}
		if err := writeAll(pw, []byte(p.body)); err != nil {
			return err
		}
	}
	return iw.Close()
}

func addressList(addrs []string) []*mail.Address {
	out := make([]*mail.Address, len(addrs))
	for i, a := range addrs {
		out[i] = &mail.Address{Address: a}
	}
	return out
}

func attachmentType(name string) string {
	if t, _, err := mime.ParseMediaType(mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))); err == nil {
		return t
	}
	return "application/octet-stream"
}

func replySubject(orig string) string {
	orig = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, orig))
	if len(orig) >= 3 && strings.EqualFold(orig[:3], "re:") {
		return orig
	}
	return "Re: " + orig
}

// auditArgs is what the log records about a send before it runs. Message text
// never appears, and the subject appears only as a hash.
func (o Outgoing) auditArgs() map[string]string {
	a := map[string]string{}
	for k, list := range map[string][]string{"to": o.To, "cc": o.Cc, "bcc": o.Bcc} {
		if len(list) > 0 {
			a[k] = strings.Join(list, ",")
		}
	}
	if o.Subject != "" {
		a["subject_sha256"] = sha256Hex([]byte(o.Subject))
	}
	if len(o.Attachments) > 0 {
		parts := make([]string, len(o.Attachments))
		for i, at := range o.Attachments {
			parts[i] = strconv.Quote(at.Name) + ":" + strconv.Itoa(len(at.Data))
		}
		a["attachments"] = strings.Join(parts, ",")
	}
	return a
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
