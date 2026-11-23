package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Spec is the unparsed form of a policy, as it appears in config.
type Spec struct {
	Allow   []string
	Deny    []string
	Actions []string
	Trash   string
	// SendTo lists the addresses and "@domain" rules that send may reach.
	SendTo []string
	// MaxRecipients caps distinct To, Cc and Bcc addresses per send. Zero
	// means DefaultMaxRecipients.
	MaxRecipients int
}

const (
	DefaultMaxRecipients = 10
	maxMaxRecipients     = 100
)

type Policy struct {
	allow         []Pattern
	deny          []Pattern
	actions       map[Action]bool
	trash         string
	sendTo        []RecipientPattern
	maxRecipients int
}

type Decision struct {
	Allowed bool
	Reason  string
}

var gmailNamespaces = []string{"[gmail]", "[google mail]"}

// isGmailSystem reports whether name lives in Gmail's system namespace
// ([Gmail]/All Mail, [Google Mail]/Trash, and so on).
func isGmailSystem(name string) bool {
	n := strings.ToLower(name)
	for _, ns := range gmailNamespaces {
		if n == ns || strings.HasPrefix(n, ns+delim) {
			return true
		}
	}
	return false
}

func New(s Spec) (Policy, error) {
	p := Policy{actions: map[Action]bool{}}
	for _, raw := range s.Allow {
		pat, err := NewPattern(raw)
		if err != nil {
			return Policy{}, fmt.Errorf("allow: %w", err)
		}
		if pat.wildcard && isGmailSystem(pat.name) {
			return Policy{}, fmt.Errorf("allow: %q cannot grant Gmail system folders; list each one by exact name", raw)
		}
		p.allow = append(p.allow, pat)
	}
	for _, raw := range s.Deny {
		pat, err := NewPattern(raw)
		if err != nil {
			return Policy{}, fmt.Errorf("deny: %w", err)
		}
		p.deny = append(p.deny, pat)
	}
	if len(s.Actions) == 0 {
		for _, a := range DefaultActions() {
			p.actions[a] = true
		}
	}
	for _, raw := range s.Actions {
		a, ok := ParseAction(raw)
		if !ok {
			return Policy{}, fmt.Errorf("actions: unknown action %q", raw)
		}
		p.actions[a] = true
	}
	for _, raw := range s.SendTo {
		pat, err := NewRecipientPattern(raw)
		if err != nil {
			return Policy{}, fmt.Errorf("send_to: %w", err)
		}
		p.sendTo = append(p.sendTo, pat)
	}
	if p.actions[Send] && len(p.sendTo) == 0 {
		return Policy{}, fmt.Errorf(`action "send" is enabled but send_to is empty; list the addresses or "@domain" rules it may reach`)
	}
	switch m := s.MaxRecipients; {
	case m == 0:
		p.maxRecipients = DefaultMaxRecipients
	case m < 0 || m > maxMaxRecipients:
		return Policy{}, fmt.Errorf("max_recipients must be between 1 and %d", maxMaxRecipients)
	default:
		p.maxRecipients = m
	}
	if s.Trash != "" {
		if err := validateName(s.Trash); err != nil {
			return Policy{}, fmt.Errorf("trash: %w", err)
		}
		p.trash = canonical(s.Trash)
	}
	return p, nil
}

// Trash is the configured delete sink, or "". It is deliberately exempt from
// the allowlist: it only receives mail and the operator chose it.
func (p Policy) Trash() string { return p.trash }

func (p Policy) ActionEnabled(a Action) bool { return p.actions[a] }

// MailboxAllowed is default deny. Deny rules win, Gmail system folders need an
// exact-name allow, and everything else needs a matching allow rule.
func (p Policy) MailboxAllowed(name string) bool {
	return p.mailboxDecision(name).Allowed
}

func (p Policy) mailboxDecision(name string) Decision {
	if err := validateName(name); err != nil {
		return Decision{Reason: fmt.Sprintf("invalid mailbox name: %v", err)}
	}
	name = canonical(name)
	for _, d := range p.deny {
		if d.matchesFold(name) {
			return Decision{Reason: fmt.Sprintf("mailbox %q matches deny rule %q", name, d)}
		}
	}
	if isGmailSystem(name) {
		for _, a := range p.allow {
			if !a.wildcard && a.name == name {
				return Decision{Allowed: true}
			}
		}
		return Decision{Reason: fmt.Sprintf("mailbox %q is a Gmail system folder and is not allowed by exact name", name)}
	}
	for _, a := range p.allow {
		if a.matches(name) {
			return Decision{Allowed: true}
		}
	}
	return Decision{Reason: fmt.Sprintf("mailbox %q is not in the allowlist", name)}
}

// Check decides whether action a may run against mailbox, and against target
// when the action takes one. It makes no network calls.
func (p Policy) Check(a Action, mailbox string, target string) Decision {
	spec, ok := Actions[a]
	if !ok {
		return Decision{Reason: fmt.Sprintf("unknown action %q", a)}
	}
	if !p.actions[a] {
		return Decision{Reason: fmt.Sprintf("action %q is not enabled", a)}
	}
	if a == Mailboxes {
		return Decision{Allowed: true}
	}
	if spec.Recipients {
		return Decision{Reason: fmt.Sprintf("action %q is checked against recipients, not a mailbox", a)}
	}
	if d := p.mailboxDecision(mailbox); !d.Allowed {
		return d
	}
	if spec.Target {
		if target == "" {
			return Decision{Reason: fmt.Sprintf("action %q needs a target mailbox", a)}
		}
		if d := p.mailboxDecision(target); !d.Allowed {
			d.Reason = "target: " + d.Reason
			return d
		}
	}
	return Decision{Allowed: true}
}

// CheckSend decides whether a message to recipients may leave. Every address
// must match send_to or nothing is sent. It names the first rejected address
// and makes no network calls.
func (p Policy) CheckSend(recipients []string) Decision {
	if !p.actions[Send] {
		return Decision{Reason: fmt.Sprintf("action %q is not enabled", Send)}
	}
	if len(recipients) == 0 {
		return Decision{Reason: "no recipients"}
	}
	distinct := map[string]bool{}
	for _, raw := range recipients {
		addr, err := normalizeAddress(raw)
		if err != nil {
			return Decision{Reason: fmt.Sprintf("recipient %q is not a plain address: %v", raw, err)}
		}
		if !p.recipientAllowed(addr) {
			return Decision{Reason: fmt.Sprintf("recipient %q is not in send_to", raw)}
		}
		distinct[addr] = true
	}
	if len(distinct) > p.maxRecipients {
		return Decision{Reason: fmt.Sprintf("%d recipients exceeds max_recipients %d", len(distinct), p.maxRecipients)}
	}
	return Decision{Allowed: true}
}

func (p Policy) recipientAllowed(addr string) bool {
	for _, r := range p.sendTo {
		if r.matches(addr) {
			return true
		}
	}
	return false
}

// Description is the effective policy as shown to the agent.
type Description struct {
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	Actions []string `json:"actions"`
	Trash   string   `json:"trash,omitempty"`
	// SendTo and MaxRecipients appear only when send is enabled.
	SendTo        []string `json:"send_to,omitempty"`
	MaxRecipients int      `json:"max_recipients,omitempty"`
}

func (p Policy) Describe() Description {
	d := Description{Allow: []string{}, Deny: []string{}, Actions: []string{}, Trash: p.trash}
	for _, a := range p.allow {
		d.Allow = append(d.Allow, a.String())
	}
	for _, x := range p.deny {
		d.Deny = append(d.Deny, x.String())
	}
	for a, on := range p.actions {
		if on {
			d.Actions = append(d.Actions, string(a))
		}
	}
	sort.Strings(d.Actions)
	if p.actions[Send] {
		d.MaxRecipients = p.maxRecipients
		for _, r := range p.sendTo {
			d.SendTo = append(d.SendTo, r.String())
		}
	}
	return d
}
