package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/momirov/scopedmail/internal/audit"
)

func quoted(s string) string { return fmt.Sprintf("%q", s) }

const filesPolicy = `allow = ["Agent", "Agent/*", "INBOX"]
actions = ["read", "attachment", "append", "send"]
send_to = ["@example.com"]
`

const secretMarker = "OUTSIDE-SECRET-MARKER"

type filesFixture struct {
	*fixture
	outside string
}

// newFilesFixture adds, beside files_dir, an outside/ directory that holds a
// secret, and symlinks inside files_dir that point at it.
func newFilesFixture(t *testing.T) *filesFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	f := newSendFixture(t, filesPolicy, "")
	ff := &filesFixture{fixture: f, outside: filepath.Join(f.dir, "outside")}
	if err := os.Mkdir(ff.outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ff.outside, "secret.txt"), []byte(secretMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"link-out":     "../outside/secret.txt",
		"dir-out":      "../outside",
		"dangling-out": "../outside/planted.txt",
	} {
		if err := os.Symlink(target, filepath.Join(f.files, name)); err != nil {
			t.Fatal(err)
		}
	}
	return ff
}

func (ff *filesFixture) escapes() []string {
	return []string{
		"../outside/secret.txt",
		filepath.Join(ff.outside, "secret.txt"),
		filepath.Join(ff.files, "..", "outside", "secret.txt"),
		"link-out",
		"dir-out/secret.txt",
		filepath.Join(ff.files, "link-out"),
	}
}

func (ff *filesFixture) assertNothingLeft(t *testing.T) {
	t.Helper()
	if n := len(ff.smtp.Deliveries()); n != 0 {
		t.Errorf("%d messages were delivered", n)
	}
	for _, d := range ff.smtp.Deliveries() {
		if bytes.Contains(d.Data, []byte(secretMarker)) {
			t.Error("the secret reached the SMTP sink")
		}
	}
	if n := ff.count("Agent"); n != 2 {
		t.Errorf("Agent holds %d messages, want the 2 seeded ones", n)
	}
	entries, _ := os.ReadDir(ff.outside)
	if len(entries) != 1 {
		t.Errorf("outside/ holds %v", entries)
	}
	if b, _ := os.ReadFile(filepath.Join(ff.outside, "secret.txt")); string(b) != secretMarker {
		t.Errorf("the secret file now holds %q", b)
	}
}

func TestSendFileFlagsRefusePathsOutsideFilesDir(t *testing.T) {
	ff := newFilesFixture(t)
	for _, flag := range []string{"--attach", "--body-file", "--html-file"} {
		for _, path := range ff.escapes() {
			r := ff.run("send", "--to", "a@example.com", "--subject", "s", "--body", "x", flag, path)
			if flag == "--body-file" {
				r = ff.run("send", "--to", "a@example.com", "--subject", "s", flag, path)
			}
			if r.exit != 3 || r.errCode(t) != "denied" {
				t.Errorf("send %s %s: exit %d stderr %s", flag, path, r.exit, r.stderr)
			}
		}
	}
	ff.assertNothingLeft(t)
	rec := ff.lastRecord()
	if rec.Action != "send" || rec.Outcome != audit.OutcomeDenied || rec.Args["file"] == "" || !strings.Contains(rec.Reason, "files_dir") {
		t.Errorf("record = %+v", rec)
	}
	if strings.Contains(ff.auditRaw(), secretMarker) {
		t.Error("the audit log holds the secret")
	}
}

func TestAppendRefusesPathsOutsideFilesDir(t *testing.T) {
	ff := newFilesFixture(t)
	for _, path := range ff.escapes() {
		if r := ff.run("append", "-m", "Agent", "--file", path); r.exit != 3 || r.errCode(t) != "denied" {
			t.Errorf("append --file %s: exit %d stderr %s", path, r.exit, r.stderr)
		}
	}
	ff.assertNothingLeft(t)
	if rec := ff.lastRecord(); rec.Action != "append" || rec.Outcome != audit.OutcomeDenied {
		t.Errorf("record = %+v", rec)
	}
}

func TestAttachmentRefusesToWriteOutsideFilesDir(t *testing.T) {
	ff := newFilesFixture(t)
	for _, path := range []string{
		"../outside/planted.txt",
		filepath.Join(ff.outside, "planted.txt"),
		"dir-out/planted.txt",
		filepath.Join(ff.files, "dir-out", "planted.txt"),
	} {
		if r := ff.run("attachment", "-m", "Agent", "2", "--part", "2", "--out", path); r.exit != 3 || r.errCode(t) != "denied" {
			t.Errorf("attachment --out %s: exit %d stderr %s", path, r.exit, r.stderr)
		}
	}
	for _, path := range []string{"link-out", "dangling-out"} {
		if r := ff.run("attachment", "-m", "Agent", "2", "--part", "2", "--out", path); r.exit == 0 {
			t.Errorf("attachment --out %s: wrote through a symlink", path)
		}
	}
	ff.assertNothingLeft(t)
	if rec := ff.records()[len(ff.records())-3]; rec.Action != "attachment" || rec.Outcome != audit.OutcomeDenied {
		t.Errorf("record = %+v", rec)
	}
}

func TestFilesInsideFilesDirWork(t *testing.T) {
	ff := newFilesFixture(t)
	if r := ff.run("attachment", "-m", "Agent", "2", "--part", "2", "--out", "got.txt"); r.exit != 0 {
		t.Fatalf("relative --out: %d %s", r.exit, r.stderr)
	} else {
		var out struct{ Path string }
		r.json(t, &out)
		if out.Path != filepath.Join(ff.files, "got.txt") {
			t.Errorf("path = %q", out.Path)
		}
	}
	if b, err := os.ReadFile(filepath.Join(ff.files, "got.txt")); err != nil || len(b) == 0 {
		t.Errorf("file: %q %v", b, err)
	}
	if r := ff.run("send", "--to", "a@example.com", "--subject", "s", "--body", "x", "--attach", "got.txt"); r.exit != 0 {
		t.Errorf("send --attach relative: %d %s", r.exit, r.stderr)
	}
	if r := ff.run("send", "--to", "a@example.com", "--subject", "s", "--body", "x", "--attach", filepath.Join(ff.files, "got.txt")); r.exit != 0 {
		t.Errorf("send --attach absolute: %d %s", r.exit, r.stderr)
	}
}

func TestFilesAreOffWithoutFilesDir(t *testing.T) {
	f := newSendFixture(t, filesPolicy, "")
	body, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.writeConfig(strings.Replace(string(body), "files_dir = "+quoted(f.files)+"\n", "", 1))
	if err := os.WriteFile(filepath.Join(f.files, "a.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"append":     {"append", "-m", "Agent", "--file", filepath.Join(f.files, "a.txt")},
		"attachment": {"attachment", "-m", "Agent", "2", "--part", "2", "--out", filepath.Join(f.files, "o.txt")},
		"send":       {"send", "--to", "a@example.com", "--subject", "s", "--attach", filepath.Join(f.files, "a.txt")},
	} {
		r := f.run(args...)
		if r.exit != 3 || !strings.Contains(r.stderr, "files_dir") {
			t.Errorf("%s: exit %d stderr %s", name, r.exit, r.stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(f.files, "o.txt")); err == nil {
		t.Error("attachment wrote a file with files off")
	}
	if r := f.run("send", "--to", "a@example.com", "--subject", "s", "--body", "no files needed"); r.exit != 0 {
		t.Errorf("send without files: %d %s", r.exit, r.stderr)
	}
	var p struct {
		FilesDir *string `json:"files_dir"`
	}
	f.run("policy").json(t, &p)
	if p.FilesDir != nil {
		t.Errorf("policy files_dir = %q, want null", *p.FilesDir)
	}
}

func TestPolicyShowsFilesDir(t *testing.T) {
	f := newFixture(t, readOnlyPolicy)
	var p struct {
		FilesDir *string `json:"files_dir"`
	}
	f.run("policy").json(t, &p)
	if p.FilesDir == nil || *p.FilesDir != f.files {
		t.Errorf("files_dir = %v, want %q", p.FilesDir, f.files)
	}
}

// With the symlink flipping between a directory inside files_dir and one
// outside, no send may carry the secret. Every run either attaches the inside
// file or is denied.
func TestSymlinkSwappedUnderARunningSendNeverLeaks(t *testing.T) {
	ff := newFilesFixture(t)
	real := filepath.Join(ff.files, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "secret.txt"), []byte("inside-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	swap := filepath.Join(ff.files, "swap")
	point := func(target string) {
		tmp := swap + ".tmp"
		os.Remove(tmp)
		if os.Symlink(target, tmp) == nil {
			os.Rename(tmp, swap)
		}
	}
	point("real")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			point([]string{"real", "../outside"}[i%2])
		}
	}()
	var sent, denied, failed int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		switch r := ff.run("send", "--to", "a@example.com", "--subject", "s", "--body", "x", "--attach", filepath.Join(ff.files, "swap", "secret.txt")); r.exit {
		case 0:
			sent++
		case 3:
			denied++
		case 1:
			failed++
		default:
			t.Errorf("exit %d: %s", r.exit, r.stderr)
		}
	}
	close(stop)
	wg.Wait()
	for _, d := range ff.smtp.Deliveries() {
		for _, body := range parseMail(t, d.Data).atts {
			if strings.Contains(body, secretMarker) {
				t.Fatal("the outside secret was sent")
			}
		}
	}
	t.Logf("%d sends attached the inside file, %d were denied, %d failed mid-swap", sent, denied, failed)
	if sent+denied+failed == 0 {
		t.Error("no run completed")
	}
}
