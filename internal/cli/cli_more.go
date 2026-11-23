package cli

import (
	"os"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/gate"
)

func runAppend(inv *invocation, args []string) error {
	fs := newFlagSet("append")
	var mailbox, file, flags string
	fs.StringVar(&mailbox, "m", "", "mailbox")
	fs.StringVar(&file, "file", "", "")
	fs.StringVar(&flags, "flags", "", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("append takes no positional arguments")
	}
	if err := needMailbox(mailbox); err != nil {
		return err
	}
	if file == "" {
		return usagef("--file is required")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return usagef("%s is not a regular file", file)
	}
	return inv.withSession(func(s *gate.Session) error {
		uid, err := s.Append(mailbox, f, info.Size(), splitCSV(flags), file)
		if err != nil {
			return err
		}
		out := map[string]any{"ok": true, "count": 1}
		if uid != 0 {
			out["uid"] = uid
		}
		writeJSON(inv.env.Stdout, out)
		return nil
	})
}

func runCreateMailbox(inv *invocation, args []string) error {
	pos, err := parse(newFlagSet("create-mailbox"), args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("create-mailbox takes exactly one NAME")
	}
	return inv.withSession(func(s *gate.Session) error {
		if err := s.CreateMailbox(pos[0]); err != nil {
			return err
		}
		writeJSON(inv.env.Stdout, writeResult{OK: true, Count: 1})
		return nil
	})
}

// runPolicy never connects and appends nothing to the audit log.
func runPolicy(inv *invocation, args []string) error {
	pos, err := parse(newFlagSet("policy"), args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("policy takes no arguments")
	}
	cfg, err := inv.loadConfig()
	if err != nil {
		return err
	}
	acct, err := cfg.Account(inv.account)
	if err != nil {
		return &codedError{"config", err}
	}
	writeJSON(inv.env.Stdout, map[string]any{"account": acct.Name, "policy": acct.Policy.Describe()})
	return nil
}

// runAudit reads the log and appends nothing to it.
func runAudit(inv *invocation, args []string) error {
	if len(args) == 0 {
		return usagef("audit needs a subcommand: verify or tail")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "verify":
		if pos, err := parse(newFlagSet("audit verify"), rest); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("audit verify takes no arguments")
		}
	case "tail":
		return auditTail(inv, rest)
	default:
		return usagef("unknown audit subcommand %q", sub)
	}
	cfg, err := inv.loadConfig()
	if err != nil {
		return err
	}
	res, err := audit.Verify(cfg.AuditLog)
	if err != nil {
		return err
	}
	writeJSON(inv.env.Stdout, map[string]any{"ok": true, "records": res.Records, "head": res.Head})
	return nil
}

func auditTail(inv *invocation, args []string) error {
	fs := newFlagSet("audit tail")
	n := fs.Int("n", 10, "number of records")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || *n < 1 {
		return usagef("audit tail [-n N] with N >= 1")
	}
	cfg, err := inv.loadConfig()
	if err != nil {
		return err
	}
	recs, err := audit.Tail(cfg.AuditLog, *n)
	if err != nil {
		return err
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(inv.env.Stdout, recs)
	return nil
}
