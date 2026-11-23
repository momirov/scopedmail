package policy

import (
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, s Spec) Policy {
	t.Helper()
	p, err := New(s)
	if err != nil {
		t.Fatalf("New(%+v): %v", s, err)
	}
	return p
}

func TestMailboxAllowed(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		box  string
		want bool
	}{
		{"default deny with empty allow", Spec{}, "INBOX", false},
		{"exact allow", Spec{Allow: []string{"Agent"}}, "Agent", true},
		{"exact allow does not cover children", Spec{Allow: []string{"Agent"}}, "Agent/Sub", false},
		{"unlisted mailbox denied", Spec{Allow: []string{"Agent"}}, "Private", false},
		{"names are case sensitive", Spec{Allow: []string{"Agent"}}, "agent", false},
		{"wildcard covers descendants", Spec{Allow: []string{"Receipts/*"}}, "Receipts/2026", true},
		{"wildcard covers deep descendants", Spec{Allow: []string{"Receipts/*"}}, "Receipts/2026/Q1", true},
		{"wildcard excludes the prefix itself", Spec{Allow: []string{"Receipts/*"}}, "Receipts", false},
		{"wildcard needs a segment boundary", Spec{Allow: []string{"Receipts/*"}}, "ReceiptsExtra/x", false},
		{"INBOX allow matches lowercase", Spec{Allow: []string{"INBOX"}}, "inbox", true},
		{"INBOX allow matches mixed case", Spec{Allow: []string{"INBOX"}}, "InBox", true},
		{"lowercase INBOX pattern matches", Spec{Allow: []string{"inbox"}}, "INBOX", true},
		{"INBOX wildcard matches case-insensitively", Spec{Allow: []string{"INBOX/*"}}, "inbox/Work", true},
		{"INBOX rule does not leak to other names", Spec{Allow: []string{"INBOX"}}, "INBOXES", false},
		{"deny wins over exact allow", Spec{Allow: []string{"Agent"}, Deny: []string{"Agent"}}, "Agent", false},
		{"deny carves a hole in a wildcard", Spec{Allow: []string{"Receipts/*"}, Deny: []string{"Receipts/Tax"}}, "Receipts/Tax", false},
		{"deny leaves siblings alone", Spec{Allow: []string{"Receipts/*"}, Deny: []string{"Receipts/Tax"}}, "Receipts/Food", true},
		{"deny is case-insensitive", Spec{Allow: []string{"Receipts/*"}, Deny: []string{"Receipts/Tax"}}, "Receipts/tax", false},
		{"deny wildcard covers descendants", Spec{Allow: []string{"Receipts/*"}, Deny: []string{"Receipts/Tax/*"}}, "Receipts/Tax/2025", false},

		{"gmail all mail denied by default", Spec{Allow: []string{"Agent"}}, "[Gmail]/All Mail", false},
		{"gmail all mail allowed by exact name", Spec{Allow: []string{"[Gmail]/All Mail"}}, "[Gmail]/All Mail", true},
		{"google mail variant denied by default", Spec{Allow: []string{"Agent"}}, "[Google Mail]/All Mail", false},
		{"google mail variant allowed by exact name", Spec{Allow: []string{"[Google Mail]/All Mail"}}, "[Google Mail]/All Mail", true},
		{"exact allow of one system folder leaves the others denied", Spec{Allow: []string{"[Gmail]/Drafts"}}, "[Gmail]/Spam", false},
		{"deny beats exact allow of system folder", Spec{Allow: []string{"[Gmail]/Drafts"}, Deny: []string{"[Gmail]/Drafts"}}, "[Gmail]/Drafts", false},
		{"system folder casing cannot dodge the rule", Spec{Allow: []string{"Agent"}}, "[GMAIL]/All Mail", false},
		{"unlisted gmail folder denied", Spec{Allow: []string{"Agent"}}, "[Gmail]/Bin", false},
		{"gmail container denied", Spec{Allow: []string{"Agent"}}, "[Gmail]", false},

		{"dotdot segment rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts/../Private", false},
		{"dot segment rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts/./x", false},
		{"empty segment rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts//x", false},
		{"trailing delimiter rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts/", false},
		{"wildcard in name rejected", Spec{Allow: []string{"Agent"}}, "Agent*", false},
		{"percent in name rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts/%", false},
		{"control char rejected", Spec{Allow: []string{"Receipts/*"}}, "Receipts/a\x00b", false},
		{"empty name rejected", Spec{Allow: []string{"Agent"}}, "", false},
		{"surrounding space rejected", Spec{Allow: []string{"Agent"}}, " Agent", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustPolicy(t, tt.spec)
			if got := p.MailboxAllowed(tt.box); got != tt.want {
				t.Errorf("MailboxAllowed(%q) = %v, want %v", tt.box, got, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	all := []string{"mailboxes", "search", "read", "attachment", "flag", "copy", "move", "delete", "append", "create-mailbox"}
	p := mustPolicy(t, Spec{
		Allow:   []string{"Agent", "Receipts/*"},
		Deny:    []string{"Receipts/Tax"},
		Actions: all,
		Trash:   "[Gmail]/Trash",
	})
	tests := []struct {
		name            string
		action          Action
		mailbox, target string
		want            bool
		reasonContains  string
	}{
		{"read allowed mailbox", Read, "Agent", "", true, ""},
		{"read denied mailbox", Read, "Private", "", false, "not in the allowlist"},
		{"search denied system folder", Search, "[Gmail]/All Mail", "", false, "Gmail system folder"},
		{"mailboxes needs no mailbox", Mailboxes, "", "", true, ""},
		{"copy needs both ends: ok", Copy, "Agent", "Receipts/Food", true, ""},
		{"copy to unallowed target denied", Copy, "Agent", "Private", false, "target:"},
		{"copy from unallowed source denied", Copy, "Private", "Agent", false, "not in the allowlist"},
		{"copy into denied target denied", Copy, "Agent", "Receipts/Tax", false, "deny rule"},
		{"copy into gmail all mail denied", Copy, "Agent", "[Gmail]/All Mail", false, "Gmail system folder"},
		{"copy without target denied", Copy, "Agent", "", false, "needs a target"},
		{"move to unallowed target denied", Move, "Agent", "Private", false, "target:"},
		{"move ok", Move, "Agent", "Receipts/Food", true, ""},
		{"delete checks only the source", Delete, "Agent", "", true, ""},
		{"delete source denied", Delete, "Private", "", false, "not in the allowlist"},
		{"flag allowed", Flag, "Agent", "", true, ""},
		{"append allowed", Append, "Agent", "", true, ""},
		{"append denied", Append, "Private", "", false, "not in the allowlist"},
		{"create-mailbox under allowed prefix", CreateMailbox, "Receipts/New", "", true, ""},
		{"create-mailbox elsewhere denied", CreateMailbox, "Elsewhere", "", false, "not in the allowlist"},
		{"unknown action denied", Action("expunge-all"), "Agent", "", false, "unknown action"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.Check(tt.action, tt.mailbox, tt.target)
			if d.Allowed != tt.want {
				t.Fatalf("Check(%s, %q, %q) = %+v, want allowed=%v", tt.action, tt.mailbox, tt.target, d, tt.want)
			}
			if !strings.Contains(d.Reason, tt.reasonContains) {
				t.Errorf("reason %q does not contain %q", d.Reason, tt.reasonContains)
			}
		})
	}
}

func TestDefaultActionsAreReadOnly(t *testing.T) {
	p := mustPolicy(t, Spec{Allow: []string{"Agent"}})
	for _, a := range AllActions() {
		want := !Actions[a].Write
		if got := p.ActionEnabled(a); got != want {
			t.Errorf("default ActionEnabled(%s) = %v, want %v", a, got, want)
		}
	}
	if d := p.Check(Copy, "Agent", "Agent/Sub"); d.Allowed || !strings.Contains(d.Reason, "not enabled") {
		t.Errorf("copy under default policy = %+v, want denied as not enabled", d)
	}
}

func TestExplicitActionsDisableTheRest(t *testing.T) {
	p := mustPolicy(t, Spec{Allow: []string{"Agent"}, Actions: []string{"read"}})
	if d := p.Check(Search, "Agent", ""); d.Allowed {
		t.Errorf("search should be disabled when only read is listed: %+v", d)
	}
	if d := p.Check(Read, "Agent", ""); !d.Allowed {
		t.Errorf("read should be enabled: %+v", d)
	}
}

func TestNewRejectsBadSpecs(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
	}{
		{"bare star allow", Spec{Allow: []string{"*"}}},
		{"bare star deny", Spec{Deny: []string{"*"}}},
		{"star in the middle", Spec{Allow: []string{"A*/b"}}},
		{"star prefix of path", Spec{Allow: []string{"*/b"}}},
		{"empty pattern", Spec{Allow: []string{""}}},
		{"empty prefix wildcard", Spec{Allow: []string{"/*"}}},
		{"dotdot in pattern", Spec{Allow: []string{"a/../b"}}},
		{"unknown action", Spec{Allow: []string{"A"}, Actions: []string{"nuke"}}},
		{"gmail wildcard allow", Spec{Allow: []string{"[Gmail]/*"}}},
		{"google mail wildcard allow", Spec{Allow: []string{"[Google Mail]/*"}}},
		{"bad trash", Spec{Trash: "a/../b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.spec); err == nil {
				t.Errorf("New(%+v) succeeded, want error", tt.spec)
			}
		})
	}
}

func TestCanonicalINBOX(t *testing.T) {
	for in, want := range map[string]string{
		"inbox":      "INBOX",
		"Inbox/Work": "INBOX/Work",
		"INBOX":      "INBOX",
		"Agent":      "Agent",
		"inboxes":    "inboxes",
	} {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTrashIsNotSubjectToTheAllowlist(t *testing.T) {
	p := mustPolicy(t, Spec{Allow: []string{"Agent"}, Actions: []string{"delete"}, Trash: "[Gmail]/Trash"})
	if p.Trash() != "[Gmail]/Trash" {
		t.Fatalf("Trash() = %q", p.Trash())
	}
	if p.MailboxAllowed("[Gmail]/Trash") {
		t.Error("the trash sink must not become readable just because it is the sink")
	}
	if d := p.Check(Delete, "Agent", ""); !d.Allowed {
		t.Errorf("delete from allowed mailbox with trash configured: %+v", d)
	}
}

func TestEveryActionHasASpecAndDefaultsAreConsistent(t *testing.T) {
	want := []Action{Mailboxes, Search, Read, Attachment, Flag, Copy, Move, Delete, Append, CreateMailbox, Send}
	if len(Actions) != len(want) {
		t.Fatalf("registry has %d actions, want %d", len(Actions), len(want))
	}
	for _, a := range want {
		if _, ok := Actions[a]; !ok {
			t.Errorf("action %s missing from registry", a)
		}
	}
	for _, a := range []Action{Copy, Move} {
		if !Actions[a].Target {
			t.Errorf("%s must take a target", a)
		}
	}
}

func sendPolicy(t *testing.T, sendTo ...string) Policy {
	t.Helper()
	return mustPolicy(t, Spec{Allow: []string{"Agent"}, Actions: []string{"send", "read"}, SendTo: sendTo})
}

func TestCheckSendMatching(t *testing.T) {
	tests := []struct {
		name     string
		sendTo   []string
		rcpts    []string
		want     bool
		rejected string
	}{
		{"exact address", []string{"alice@example.com"}, []string{"alice@example.com"}, true, ""},
		{"exact address ignores case", []string{"Alice@Example.COM"}, []string{"aLICE@example.com"}, true, ""},
		{"exact address does not cover siblings", []string{"alice@example.com"}, []string{"bob@example.com"}, false, "bob@example.com"},
		{"domain rule covers any local part", []string{"@example.com"}, []string{"anyone@example.com", "x.y+z@example.com"}, true, ""},
		{"domain rule ignores case", []string{"@Example.COM"}, []string{"a@EXAMPLE.com"}, true, ""},
		{"domain rule excludes subdomains", []string{"@example.com"}, []string{"a@mail.example.com"}, false, "a@mail.example.com"},
		{"domain rule excludes parent domain", []string{"@mail.example.com"}, []string{"a@example.com"}, false, "a@example.com"},
		{"domain rule is not a suffix match", []string{"@example.com"}, []string{"a@evilexample.com"}, false, "a@evilexample.com"},
		{"address containing the domain string is not a match", []string{"@example.com"}, []string{"example.com@evil.com"}, false, "example.com@evil.com"},
		{"local part spelled like the domain does not match", []string{"@example.com"}, []string{"a@example.com.evil.com"}, false, "a@example.com.evil.com"},
		{"quoted local part cannot smuggle a domain", []string{"@example.com"}, []string{`"a@example.com"@evil.com`}, false, "evil.com"},
		{"second at sign rejected", []string{"@example.com"}, []string{"a@evil.com@example.com"}, false, "a@evil.com@example.com"},
		{"display form rejected", []string{"@example.com"}, []string{"Alice <a@example.com>"}, false, "Alice <a@example.com>"},
		{"header injection rejected", []string{"@example.com"}, []string{"a@example.com\r\nBcc: x@evil.com"}, false, "a@example.com"},
		{"non-ascii domain rejected", []string{"@example.com"}, []string{"a@exampl\u0435.com"}, false, ""},
		{"first rejected address is named", []string{"@example.com"}, []string{"ok@example.com", "bad@evil.com", "worse@evil.org"}, false, "bad@evil.com"},
		{"one bad bcc blocks the whole send", []string{"ok@example.com"}, []string{"ok@example.com", "secret@evil.com"}, false, "secret@evil.com"},
		{"either rule suffices", []string{"alice@other.org", "@example.com"}, []string{"alice@other.org", "b@example.com"}, true, ""},
		{"no recipients", []string{"@example.com"}, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := sendPolicy(t, tt.sendTo...).CheckSend(tt.rcpts)
			if d.Allowed != tt.want {
				t.Fatalf("CheckSend(%q) = %+v, want allowed=%v", tt.rcpts, d, tt.want)
			}
			if tt.rejected != "" && !strings.Contains(d.Reason, tt.rejected) {
				t.Errorf("reason %q does not name %q", d.Reason, tt.rejected)
			}
		})
	}
}

func TestCheckSendDoesNotNameLaterAddresses(t *testing.T) {
	d := sendPolicy(t, "@example.com").CheckSend([]string{"bad@evil.com", "worse@evil.org"})
	if strings.Contains(d.Reason, "worse@evil.org") {
		t.Errorf("reason %q names a later rejected address", d.Reason)
	}
}

func TestCheckSendMaxRecipients(t *testing.T) {
	p := mustPolicy(t, Spec{Actions: []string{"send"}, SendTo: []string{"@example.com"}, MaxRecipients: 2})
	if d := p.CheckSend([]string{"a@example.com", "b@example.com"}); !d.Allowed {
		t.Errorf("two recipients under max 2: %+v", d)
	}
	if d := p.CheckSend([]string{"a@example.com", "A@EXAMPLE.com"}); !d.Allowed {
		t.Errorf("duplicates count once: %+v", d)
	}
	if d := p.CheckSend([]string{"a@example.com", "b@example.com", "c@example.com"}); d.Allowed || !strings.Contains(d.Reason, "max_recipients") {
		t.Errorf("three recipients over max 2: %+v", d)
	}
	def := mustPolicy(t, Spec{Actions: []string{"send"}, SendTo: []string{"@example.com"}})
	var eleven []string
	for i := range 11 {
		eleven = append(eleven, string(rune('a'+i))+"@example.com")
	}
	if d := def.CheckSend(eleven[:10]); !d.Allowed {
		t.Errorf("default allows 10: %+v", d)
	}
	if d := def.CheckSend(eleven); d.Allowed {
		t.Error("default must reject 11")
	}
}

func TestSendIsOffByDefaultAndNeedsSendTo(t *testing.T) {
	if _, ok := map[Action]bool{}[Send]; ok || mustPolicy(t, Spec{Allow: []string{"Agent"}}).ActionEnabled(Send) {
		t.Error("send must not be in the default action set")
	}
	for _, a := range DefaultActions() {
		if a == Send {
			t.Error("DefaultActions contains send")
		}
	}
	if d := mustPolicy(t, Spec{Allow: []string{"Agent"}}).CheckSend([]string{"a@example.com"}); d.Allowed || !strings.Contains(d.Reason, "not enabled") {
		t.Errorf("send under default policy = %+v", d)
	}
	if _, err := New(Spec{Actions: []string{"send"}}); err == nil || !strings.Contains(err.Error(), "send_to is empty") {
		t.Errorf("send without send_to: err = %v", err)
	}
}

func TestSendToCheckedByCheckNeverAllows(t *testing.T) {
	p := sendPolicy(t, "@example.com")
	if d := p.Check(Send, "Agent", ""); d.Allowed {
		t.Errorf("Check(send) must defer to CheckSend: %+v", d)
	}
}

func TestNewRejectsBadSendSpecs(t *testing.T) {
	bad := []Spec{
		{SendTo: []string{"*"}},
		{SendTo: []string{"example.com"}},
		{SendTo: []string{"@"}},
		{SendTo: []string{"@com"}},
		{SendTo: []string{"@*.example.com"}},
		{SendTo: []string{"@.example.com"}},
		{SendTo: []string{"@example..com"}},
		{SendTo: []string{"@-example.com"}},
		{SendTo: []string{"@1.2.3.4"}},
		{SendTo: []string{"*@example.com"}},
		{SendTo: []string{"a%b@example.com"}},
		{SendTo: []string{"@example.com@evil.com"}},
		{SendTo: []string{"a@b@example.com"}},
		{SendTo: []string{"Alice <a@example.com>"}},
		{SendTo: []string{"a b@example.com"}},
		{SendTo: []string{"@example.com\n"}},
		{SendTo: []string{""}},
		{SendTo: []string{"@example.com"}, MaxRecipients: -1},
		{SendTo: []string{"@example.com"}, MaxRecipients: 101},
	}
	for _, s := range bad {
		if _, err := New(s); err == nil {
			t.Errorf("New(%q) succeeded, want error", s.SendTo)
		}
	}
}

func TestDescribeShowsSendRulesOnlyWhenEnabled(t *testing.T) {
	d := mustPolicy(t, Spec{Allow: []string{"Agent"}, Actions: []string{"send"}, SendTo: []string{"Bob@Example.com", "@example.org"}, MaxRecipients: 3}).Describe()
	if got := strings.Join(d.SendTo, ","); got != "bob@example.com,@example.org" || d.MaxRecipients != 3 {
		t.Errorf("Describe = %+v", d)
	}
	off := mustPolicy(t, Spec{Allow: []string{"Agent"}, SendTo: []string{"@example.org"}}).Describe()
	if len(off.SendTo) != 0 || off.MaxRecipients != 0 {
		t.Errorf("send rules shown while send is disabled: %+v", off)
	}
}
