// Package cli maps command lines onto gate.Session calls and renders JSON.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/config"
	"github.com/momirov/scopedmail/internal/gate"
)

const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitDenied = 3
)

type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// codedError carries a stable machine-readable code for the error JSON.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

type invocation struct {
	env        Env
	configPath string
	account    string
}

type command struct {
	name  string
	usage string
	run   func(inv *invocation, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"mailboxes", "mailboxes", runMailboxes},
		{"search", "search -m MBOX [--from S --to S --subject S --body S --text S --since DATE --before DATE --seen|--unseen --flagged --limit N]", runSearch},
		{"read", "read -m MBOX UID [--raw] [--html]", runRead},
		{"attachment", "attachment -m MBOX UID --part P --out FILE", runAttachment},
		{"flag", "flag -m MBOX [--add F,..] [--remove F,..] UID...", runFlag},
		{"copy", "copy -m MBOX --to MBOX UID...", runCopy},
		{"move", "move -m MBOX --to MBOX UID...", runMove},
		{"delete", "delete -m MBOX UID...", runDelete},
		{"append", "append -m MBOX --file MSG.eml [--flags draft,seen]", runAppend},
		{"create-mailbox", "create-mailbox NAME", runCreateMailbox},
		{"policy", "policy", runPolicy},
		{"audit", "audit verify | audit tail [-n N]", runAudit},
	}
}

func usageText() string {
	var b strings.Builder
	b.WriteString("usage: scopedmail [--config PATH] [--account NAME] <command>\n\ncommands:\n")
	for _, c := range commands {
		b.WriteString("  " + c.usage + "\n")
	}
	b.WriteString("\nexit codes: 0 ok, 1 error, 2 usage, 3 denied by policy\n")
	return b.String()
}

// Run executes one scopedmail invocation and returns its exit code.
func Run(args []string, env Env) int {
	inv := &invocation{env: env}
	fs := newFlagSet("scopedmail")
	fs.StringVar(&inv.configPath, "config", "", "config file")
	fs.StringVar(&inv.account, "account", "", "account name")
	err := fs.Parse(args)
	rest := fs.Args()
	switch {
	case errors.Is(err, flag.ErrHelp) || (err == nil && len(rest) == 1 && rest[0] == "help"):
		io.WriteString(env.Stdout, usageText())
		return exitOK
	case err != nil:
		return fail(env, usagef("%v", err))
	case len(rest) == 0:
		return fail(env, usagef("missing command\n\n%s", usageText()))
	}
	for _, c := range commands {
		if c.name == rest[0] {
			if err := c.run(inv, rest[1:]); err != nil {
				return fail(env, err)
			}
			return exitOK
		}
	}
	return fail(env, usagef("unknown command %q\n\n%s", rest[0], usageText()))
}

func fail(env Env, err error) int {
	var (
		denied *gate.DeniedError
		gUsage *gate.UsageError
		cUsage *usageError
		auditE *gate.AuditError
		broken *audit.BrokenError
		coded  *codedError
	)
	code, exit := "error", exitError
	switch {
	case errors.As(err, &denied):
		code, exit = "denied", exitDenied
	case errors.As(err, &cUsage), errors.As(err, &gUsage):
		code, exit = "usage", exitUsage
	case errors.As(err, &auditE):
		code = "audit"
	case errors.As(err, &broken):
		code = "audit_broken"
	case errors.As(err, &coded):
		code = coded.code
	}
	writeJSON(env.Stderr, map[string]any{"error": map[string]string{"code": code, "message": err.Error()}})
	return exit
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse accepts flags before, between, and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usagef("%s: %v", fs.Name(), err)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos, args = append(pos, args[0]), args[1:]
	}
}

func parseUIDs(args []string) ([]uint32, error) {
	if len(args) == 0 {
		return nil, usagef("at least one UID is required")
	}
	uids := make([]uint32, len(args))
	for i, a := range args {
		n, err := strconv.ParseUint(a, 10, 32)
		if err != nil || n == 0 {
			return nil, usagef("invalid UID %q", a)
		}
		uids[i] = uint32(n)
	}
	return uids, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func needMailbox(mailbox string) error {
	if mailbox == "" {
		return usagef("-m MBOX is required")
	}
	return nil
}

func (inv *invocation) loadConfig() (*config.Config, error) {
	path, err := config.DefaultPath(inv.configPath, inv.env.Getenv)
	if err != nil {
		return nil, &codedError{"config", err}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, &codedError{"config", err}
	}
	return cfg, nil
}

// withSession loads config, opens and locks the audit log, and only then
// builds the gate. A failure at any step stops the command before a connection
// exists.
func (inv *invocation) withSession(f func(*gate.Session) error) error {
	cfg, err := inv.loadConfig()
	if err != nil {
		return err
	}
	acct, err := cfg.Account(inv.account)
	if err != nil {
		return &codedError{"config", err}
	}
	log, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return &codedError{"audit", err}
	}
	defer log.Close()
	sess := gate.New(acct.Name, acct.Policy, log, gate.Dialer(acct))
	defer sess.Close()
	return f(sess)
}

func runMailboxes(inv *invocation, args []string) error {
	pos, err := parse(newFlagSet("mailboxes"), args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("mailboxes takes no arguments")
	}
	return inv.withSession(func(s *gate.Session) error {
		out, err := s.Mailboxes()
		if err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, out)
		return nil
	})
}

func parseDate(name, s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return t, usagef("--%s: want YYYY-MM-DD, got %q", name, s)
	}
	return t, nil
}

const maxLimit = 1000

func runSearch(inv *invocation, args []string) error {
	fs := newFlagSet("search")
	var q gate.SearchQuery
	var mailbox, since, before string
	var seen, unseen bool
	fs.StringVar(&mailbox, "m", "", "mailbox")
	fs.StringVar(&q.From, "from", "", "")
	fs.StringVar(&q.To, "to", "", "")
	fs.StringVar(&q.Subject, "subject", "", "")
	fs.StringVar(&q.Body, "body", "", "")
	fs.StringVar(&q.Text, "text", "", "")
	fs.StringVar(&since, "since", "", "")
	fs.StringVar(&before, "before", "", "")
	fs.BoolVar(&seen, "seen", false, "")
	fs.BoolVar(&unseen, "unseen", false, "")
	fs.BoolVar(&q.Flagged, "flagged", false, "")
	fs.IntVar(&q.Limit, "limit", 50, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("search takes no positional arguments")
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	if seen && unseen {
		return usagef("--seen and --unseen are mutually exclusive")
	}
	if q.Limit < 1 || q.Limit > maxLimit {
		return usagef("--limit must be between 1 and %d", maxLimit)
	}
	switch {
	case seen:
		q.Seen = gate.SeenOnly
	case unseen:
		q.Seen = gate.UnseenOnly
	}
	if q.Since, err = parseDate("since", since); err != nil {
		return err
	}
	if q.Before, err = parseDate("before", before); err != nil {
		return err
	}
	return inv.withSession(func(s *gate.Session) error {
		out, err := s.Search(mailbox, q)
		if err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, out)
		return nil
	})
}

func runRead(inv *invocation, args []string) error {
	fs := newFlagSet("read")
	var mailbox string
	var opt gate.ReadOptions
	fs.StringVar(&mailbox, "m", "", "mailbox")
	fs.BoolVar(&opt.Raw, "raw", false, "")
	fs.BoolVar(&opt.HTML, "html", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	uids, err := parseUIDs(pos)
	if err != nil {
		return err
	}
	if len(uids) != 1 {
		return usagef("read takes exactly one UID")
	}
	return inv.withSession(func(s *gate.Session) error {
		out, err := s.Read(mailbox, uids[0], opt)
		if err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, out)
		return nil
	})
}

func runAttachment(inv *invocation, args []string) error {
	fs := newFlagSet("attachment")
	var mailbox, part, out string
	fs.StringVar(&mailbox, "m", "", "mailbox")
	fs.StringVar(&part, "part", "", "")
	fs.StringVar(&out, "out", "", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	if part == "" || out == "" {
		return usagef("--part and --out are required")
	}
	uids, err := parseUIDs(pos)
	if err != nil {
		return err
	}
	if len(uids) != 1 {
		return usagef("attachment takes exactly one UID")
	}
	return inv.withSession(func(s *gate.Session) error {
		res, err := s.Attachment(mailbox, uids[0], part, out)
		if err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, res)
		return nil
	})
}

type writeResult struct {
	OK       bool     `json:"ok"`
	Count    int      `json:"count"`
	DestUIDs []uint32 `json:"dest_uids,omitempty"`
}

func runFlag(inv *invocation, args []string) error {
	fs := newFlagSet("flag")
	var mailbox, add, remove string
	fs.StringVar(&mailbox, "m", "", "mailbox")
	fs.StringVar(&add, "add", "", "")
	fs.StringVar(&remove, "remove", "", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	if add == "" && remove == "" {
		return usagef("--add or --remove is required")
	}
	uids, err := parseUIDs(pos)
	if err != nil {
		return err
	}
	return inv.withSession(func(s *gate.Session) error {
		if err := s.Flag(mailbox, uids, splitCSV(add), splitCSV(remove)); err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, writeResult{OK: true, Count: len(uids)})
		return nil
	})
}

func transfer(name string, do func(*gate.Session, string, string, []uint32) ([]uint32, error)) func(*invocation, []string) error {
	return func(inv *invocation, args []string) error {
		fs := newFlagSet(name)
		var mailbox, to string
		fs.StringVar(&mailbox, "m", "", "mailbox")
		fs.StringVar(&to, "to", "", "target mailbox")
		pos, err := parse(fs, args)
		if err != nil {
			return err
		}
		if err := needMailbox(mailbox); err != nil {
			return err
		}
		if to == "" {
			return usagef("--to MBOX is required")
		}
		uids, err := parseUIDs(pos)
		if err != nil {
			return err
		}
		return inv.withSession(func(s *gate.Session) error {
			dest, err := do(s, mailbox, to, uids)
			if err != nil {
				return err
			}
			writeJSON(inv.env.Stdout, writeResult{OK: true, Count: len(uids), DestUIDs: dest})
			return nil
		})
	}
}

var (
	runCopy = transfer("copy", (*gate.Session).Copy)
	runMove = transfer("move", (*gate.Session).Move)
)

func runDelete(inv *invocation, args []string) error {
	fs := newFlagSet("delete")
	var mailbox string
	fs.StringVar(&mailbox, "m", "", "mailbox")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	uids, err := parseUIDs(pos)
	if err != nil {
		return err
	}
	return inv.withSession(func(s *gate.Session) error {
		if err := s.Delete(mailbox, uids); err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, writeResult{OK: true, Count: len(uids)})
		return nil
	})
}
