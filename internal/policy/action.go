package policy

import "sort"

type Action string

const (
	Mailboxes     Action = "mailboxes"
	Search        Action = "search"
	Read          Action = "read"
	Attachment    Action = "attachment"
	Flag          Action = "flag"
	Copy          Action = "copy"
	Move          Action = "move"
	Delete        Action = "delete"
	Append        Action = "append"
	CreateMailbox Action = "create-mailbox"
	Send          Action = "send"
)

type ActionSpec struct {
	// Write is true when the action mutates server state.
	Write bool
	// Target is true when the action takes a destination mailbox that must
	// also pass the allowlist.
	Target bool
	// Recipients is true when the action addresses outside people, so the
	// recipient allowlist applies instead of a mailbox.
	Recipients bool
}

// Actions is the single source of truth for what scopedmail can do. Every CLI
// command maps to exactly one entry, and the gate refuses anything absent here.
var Actions = map[Action]ActionSpec{
	Mailboxes:     {},
	Search:        {},
	Read:          {},
	Attachment:    {},
	Flag:          {Write: true},
	Copy:          {Write: true, Target: true},
	Move:          {Write: true, Target: true},
	Delete:        {Write: true},
	Append:        {Write: true},
	CreateMailbox: {Write: true},
	Send:          {Write: true, Recipients: true},
}

func ParseAction(s string) (Action, bool) {
	a := Action(s)
	_, ok := Actions[a]
	return a, ok
}

// AllActions returns every registered action in a stable order.
func AllActions() []Action {
	out := make([]Action, 0, len(Actions))
	for a := range Actions {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DefaultActions is the read-only set enabled when a policy lists no actions.
func DefaultActions() []Action {
	var out []Action
	for _, a := range AllActions() {
		if !Actions[a].Write {
			out = append(out, a)
		}
	}
	return out
}
