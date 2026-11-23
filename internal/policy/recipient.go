package policy

import (
	"fmt"
	"strings"
)

// RecipientPattern is a send_to rule: an exact address ("alice@example.com") or
// a whole domain ("@example.com"). A domain rule matches that domain only, not
// its subdomains.
type RecipientPattern struct {
	addr   string
	domain string
}

func NewRecipientPattern(raw string) (RecipientPattern, error) {
	if dom, ok := strings.CutPrefix(raw, "@"); ok {
		d, err := normalizeDomain(dom)
		if err != nil {
			return RecipientPattern{}, fmt.Errorf("pattern %q: %w", raw, err)
		}
		return RecipientPattern{domain: d}, nil
	}
	a, err := normalizeAddress(raw)
	if err != nil {
		return RecipientPattern{}, fmt.Errorf("pattern %q: %w", raw, err)
	}
	return RecipientPattern{addr: a}, nil
}

func (r RecipientPattern) String() string {
	if r.domain != "" {
		return "@" + r.domain
	}
	return r.addr
}

// matches expects an address already passed through normalizeAddress.
func (r RecipientPattern) matches(addr string) bool {
	if r.domain != "" {
		_, dom, _ := strings.Cut(addr, "@")
		return dom == r.domain
	}
	return addr == r.addr
}

// localExtra is what an unquoted local part may hold besides letters, digits
// and dots. It leaves out RFC atext characters such as * % ! and /, which are
// wildcard, source-route and path syntax in other systems.
const localExtra = "_-+'"

// normalizeAddress accepts only a plain ASCII addr-spec with an unquoted local
// part and returns it lowercased. It is deliberately stricter than RFC 5322:
// quoted local parts, comments and IP literals are how an allowlist gets
// confused about which domain an address really belongs to. Matching is
// case-insensitive on the whole address, as the operator asked.
func normalizeAddress(s string) (string, error) {
	local, dom, ok := strings.Cut(s, "@")
	if !ok || strings.Contains(dom, "@") {
		return "", fmt.Errorf("want exactly one @ in an address")
	}
	if local == "" || len(local) > 64 {
		return "", fmt.Errorf("local part must be 1 to 64 characters")
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", fmt.Errorf("local part has a misplaced dot")
	}
	for _, r := range local {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || strings.ContainsRune(localExtra, r)
		if !ok {
			return "", fmt.Errorf("local part contains %q, which is not allowed", r)
		}
	}
	d, err := normalizeDomain(dom)
	if err != nil {
		return "", err
	}
	return strings.ToLower(local) + "@" + d, nil
}

func normalizeDomain(s string) (string, error) {
	if s == "" || len(s) > 253 {
		return "", fmt.Errorf("domain must be 1 to 253 characters")
	}
	labels := strings.Split(strings.ToLower(s), ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q needs at least two labels", s)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("domain %q has an invalid label", s)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("domain %q contains %q, which is not allowed", s, r)
			}
		}
	}
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return "", fmt.Errorf("domain %q has an all-numeric last label", s)
	}
	return strings.ToLower(s), nil
}
