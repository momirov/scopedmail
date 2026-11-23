package policy

import (
	"fmt"
	"strings"
	"unicode"
)

const delim = "/"

// Pattern is either an exact mailbox name or "Prefix/*", which matches every
// strict descendant of Prefix and not Prefix itself.
type Pattern struct {
	name     string
	wildcard bool
}

func NewPattern(raw string) (Pattern, error) {
	if raw == "*" {
		return Pattern{}, fmt.Errorf("bare %q is not allowed; name each mailbox or use \"Prefix/*\"", raw)
	}
	if prefix, ok := strings.CutSuffix(raw, delim+"*"); ok {
		if err := validateName(prefix); err != nil {
			return Pattern{}, fmt.Errorf("pattern %q: %w", raw, err)
		}
		return Pattern{name: canonical(prefix), wildcard: true}, nil
	}
	if err := validateName(raw); err != nil {
		return Pattern{}, fmt.Errorf("pattern %q: %w", raw, err)
	}
	return Pattern{name: canonical(raw)}, nil
}

func (p Pattern) String() string {
	if p.wildcard {
		return p.name + delim + "*"
	}
	return p.name
}

// matches is case-sensitive apart from the INBOX rule that canonical applies.
func (p Pattern) matches(name string) bool {
	if p.wildcard {
		return strings.HasPrefix(name, p.name+delim)
	}
	return name == p.name
}

// matchesFold is for deny rules. Servers such as Gmail resolve labels
// case-insensitively, so a case-sensitive deny would let "receipts/tax" slip
// past a deny on "Receipts/Tax".
func (p Pattern) matchesFold(name string) bool {
	n, pn := strings.ToLower(name), strings.ToLower(p.name)
	if p.wildcard {
		return strings.HasPrefix(n, pn+delim)
	}
	return n == pn
}

// canonical applies RFC 3501's rule that INBOX is case-insensitive.
func canonical(name string) string {
	first, rest, hasRest := strings.Cut(name, delim)
	if !strings.EqualFold(first, "INBOX") {
		return name
	}
	if hasRest {
		return "INBOX" + delim + rest
	}
	return "INBOX"
}

// Canonical returns the name the gate sends to the server.
func Canonical(name string) string { return canonical(name) }

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("empty mailbox name")
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("mailbox name has leading or trailing space")
	}
	for _, r := range name {
		switch {
		case unicode.IsControl(r):
			return fmt.Errorf("mailbox name contains a control character")
		case r == '*' || r == '%':
			return fmt.Errorf("mailbox name contains the wildcard %q", r)
		}
	}
	for _, seg := range strings.Split(name, delim) {
		switch seg {
		case "":
			return fmt.Errorf("mailbox name has an empty path segment")
		case ".", "..":
			return fmt.Errorf("mailbox name has a %q path segment", seg)
		}
	}
	return nil
}
