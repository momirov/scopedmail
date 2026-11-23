package cli

import (
	"flag"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/momirov/scopedmail/internal/gate"
)

// multiFlag collects a repeatable flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// readAgentFile is the one place send reads a path the agent supplied
// (--body-file, --html-file, --attach). Whatever limits which files an agent
// may read belongs here and nowhere else.
func readAgentFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, usagef("%s is not a regular file", path)
	}
	return readCapped(f, path)
}

func readCapped(r io.Reader, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, gate.MaxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > gate.MaxMessageBytes {
		return nil, usagef("%s is larger than the %d byte message limit", what, gate.MaxMessageBytes)
	}
	return data, nil
}

// noCRLF rejects header injection in a value that will end up in a header or a
// file name, before anything is parsed.
func noCRLF(flagName, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return usagef("--%s contains a line break", flagName)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return usagef("--%s contains a control character", flagName)
		}
	}
	return nil
}

// parseAddresses turns a comma-separated flag into bare addresses. Display
// names are dropped: only the address is ever sent or checked.
func parseAddresses(flagName, v string) ([]string, error) {
	if v == "" {
		return nil, nil
	}
	if err := noCRLF(flagName, v); err != nil {
		return nil, err
	}
	list, err := mail.ParseAddressList(v)
	if err != nil {
		return nil, usagef("--%s: %v", flagName, err)
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	if len(out) == 0 {
		return nil, usagef("--%s names no address", flagName)
	}
	return out, nil
}

func runSend(inv *invocation, args []string) error {
	fs := newFlagSet("send")
	var to, cc, bcc, subject, body, bodyFile, htmlFile, mailbox string
	var attach multiFlag
	var reply bool
	fs.StringVar(&to, "to", "", "")
	fs.StringVar(&cc, "cc", "", "")
	fs.StringVar(&bcc, "bcc", "", "")
	fs.StringVar(&subject, "subject", "", "")
	fs.StringVar(&body, "body", "", "")
	fs.StringVar(&bodyFile, "body-file", "", "")
	fs.StringVar(&htmlFile, "html-file", "", "")
	fs.Var(&attach, "attach", "")
	fs.BoolVar(&reply, "reply-to", false, "")
	fs.StringVar(&mailbox, "m", "", "mailbox")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	bodySet := false
	fs.Visit(func(f *flag.Flag) { bodySet = bodySet || f.Name == "body" })

	var out gate.Outgoing
	for _, a := range []struct {
		name string
		raw  string
		dst  *[]string
	}{{"to", to, &out.To}, {"cc", cc, &out.Cc}, {"bcc", bcc, &out.Bcc}} {
		if *a.dst, err = parseAddresses(a.name, a.raw); err != nil {
			return err
		}
	}
	if err := noCRLF("subject", subject); err != nil {
		return err
	}
	out.Subject = subject

	if reply {
		if err := needMailbox(mailbox); err != nil {
			return err
		}
		uids, err := parseUIDs(pos)
		if err != nil {
			return err
		}
		if len(uids) != 1 {
			return usagef("--reply-to takes exactly one UID")
		}
		out.Reply = &gate.ReplyRef{Mailbox: mailbox, UID: uids[0]}
	} else if mailbox != "" || len(pos) > 0 {
		return usagef("send takes -m MBOX UID only with --reply-to")
	}

	if bodySet && bodyFile != "" {
		return usagef("--body and --body-file are mutually exclusive")
	}
	switch {
	case bodySet:
		out.Text = body
	case bodyFile != "":
		b, err := readAgentFile(bodyFile)
		if err != nil {
			return err
		}
		out.Text = string(b)
	case inv.env.Stdin != nil:
		b, err := readCapped(inv.env.Stdin, "stdin")
		if err != nil {
			return err
		}
		out.Text = string(b)
	}
	if htmlFile != "" {
		b, err := readAgentFile(htmlFile)
		if err != nil {
			return err
		}
		out.HTML = string(b)
	}
	for _, path := range attach {
		if err := noCRLF("attach", path); err != nil {
			return err
		}
		data, err := readAgentFile(path)
		if err != nil {
			return err
		}
		out.Attachments = append(out.Attachments, gate.Attachment{Name: filepath.Base(path), Data: data})
	}

	return inv.withSession(func(s *gate.Session) error {
		res, err := s.Send(out)
		if err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, map[string]any{"ok": true, "message_id": res.MessageID, "recipients": res.Recipients})
		return nil
	})
}
