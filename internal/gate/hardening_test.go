package gate_test

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/momirov/scopedmail/internal/audit"
	"github.com/momirov/scopedmail/internal/gate"
	"github.com/momirov/scopedmail/internal/policy"
	"github.com/momirov/scopedmail/internal/testserver"
)

const draftEML = "From: a@example.test\r\nSubject: draft\r\n\r\nbody\r\n"

func TestCustomKeywordsAreDeniedByDefault(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions}, testserver.Options{})
	for name, do := range map[string]func() error{
		"flag --add":    func() error { return e.sess.Flag("Agent", []uint32{1}, []string{"seen", "Project"}, nil) },
		"flag --remove": func() error { return e.sess.Flag("Agent", []uint32{1}, nil, []string{"Project"}) },
		"append --flags": func() error {
			_, err := e.sess.Append("Agent", strings.NewReader(draftEML), int64(len(draftEML)), []string{"draft", "Project"}, "")
			return err
		},
	} {
		e.srv.ResetCommands()
		var denied *gate.DeniedError
		if err := do(); !errors.As(err, &denied) || !strings.Contains(denied.Reason, "allow_keywords") {
			t.Errorf("%s: err = %v, want a denial naming allow_keywords", name, err)
		}
		if cmds := e.commands(); strings.Contains(cmds, "STORE") || strings.Contains(cmds, "APPEND") {
			t.Errorf("%s reached the server:\n%s", name, cmds)
		}
		if last := e.records(t); last[len(last)-1].Outcome != audit.OutcomeDenied {
			t.Errorf("%s: last record = %+v", name, last[len(last)-1])
		}
	}
	if err := e.sess.Flag("Agent", []uint32{1}, []string{"seen", "flagged", "answered", "draft"}, nil); err != nil {
		t.Errorf("system flags: %v", err)
	}
}

func TestAllowKeywordsLetsCustomKeywordsThrough(t *testing.T) {
	e := setup(t, policy.Spec{Allow: []string{"Agent"}, Actions: allActions, AllowKeywords: true}, testserver.Options{})
	if err := e.sess.Flag("Agent", []uint32{1}, []string{"Project"}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.commands(), "Project") {
		t.Errorf("the keyword was not stored:\n%s", e.commands())
	}
}

func TestWritableCAFileIsRefusedBeforeConnecting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows has no comparable mode bits")
	}
	e := setup(t, policy.Spec{Allow: []string{"Agent"}}, testserver.Options{})
	if err := os.Chmod(e.acct.TLSCAFile, 0o666); err != nil {
		t.Fatal(err)
	}
	e.srv.ResetCommands()
	_, err := e.sess.Search("Agent", gate.SearchQuery{Limit: 1})
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("err = %v, want a refused tls_ca_file", err)
	}
	if cmds := e.commands(); strings.Contains(cmds, "LOGIN") {
		t.Errorf("logged in with a CA file others can replace:\n%s", cmds)
	}
}
