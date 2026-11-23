package agentfs_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/momirov/scopedmail/internal/agentfs"
)

const (
	secret  = "OUTSIDE-SECRET"
	inbound = "inside-content"
)

type layout struct {
	base, files, outside string
}

// newLayout builds files/ (the allowed directory) beside outside/ (which holds
// a secret), with symlinks that point out of files/ and one that stays in.
func newLayout(t *testing.T) layout {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	base := t.TempDir()
	l := layout{base: base, files: filepath.Join(base, "files"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{l.files, filepath.Join(l.files, "sub"), l.outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(l.outside, "secret.txt"), secret)
	write(filepath.Join(l.files, "ok.txt"), inbound)
	write(filepath.Join(l.files, "sub", "in.txt"), inbound)
	for name, target := range map[string]string{
		"link-out":      "../outside/secret.txt",
		"dir-out":       "../outside",
		"abs-link-out":  filepath.Join(l.outside, "secret.txt"),
		"dangling-out":  "../outside/new.txt",
		"link-in":       "ok.txt",
		"sub/up-escape": "../../outside/secret.txt",
	} {
		if err := os.Symlink(target, filepath.Join(l.files, name)); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func isDenied(err error) bool {
	var d *agentfs.Denied
	return errors.As(err, &d)
}

func TestOpenDeniesEveryEscape(t *testing.T) {
	l := newLayout(t)
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	for _, path := range []string{
		"../outside/secret.txt",
		"sub/../../outside/secret.txt",
		filepath.Join(l.outside, "secret.txt"),
		filepath.Join(l.files, "..", "outside", "secret.txt"),
		"/etc/passwd",
		"link-out",
		"abs-link-out",
		"dir-out/secret.txt",
		"sub/up-escape",
		filepath.Join(l.files, "link-out"),
		filepath.Join(l.files, "dir-out", "secret.txt"),
	} {
		f, _, err := d.Open(path)
		if err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Errorf("Open(%q) succeeded and read %q", path, b)
			continue
		}
		if !isDenied(err) {
			t.Errorf("Open(%q) = %v, want a denial", path, err)
		}
	}
}

func TestOpenAllowsPathsInsideFilesDir(t *testing.T) {
	l := newLayout(t)
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	for _, path := range []string{"ok.txt", "./ok.txt", "sub/in.txt", "sub/../ok.txt", "link-in", filepath.Join(l.files, "ok.txt"), filepath.Join(l.files, "sub", "in.txt")} {
		f, _, err := d.Open(path)
		if err != nil {
			t.Errorf("Open(%q): %v", path, err)
			continue
		}
		if b, _ := io.ReadAll(f); string(b) != inbound {
			t.Errorf("Open(%q) read %q", path, b)
		}
		f.Close()
	}
}

func TestAbsolutePathThroughASymlinkedFilesDir(t *testing.T) {
	l := newLayout(t)
	alias := filepath.Join(l.base, "alias")
	if err := os.Symlink(l.files, alias); err != nil {
		t.Fatal(err)
	}
	d := agentfs.New(alias)
	t.Cleanup(func() { d.Close() })
	for _, path := range []string{filepath.Join(alias, "ok.txt"), filepath.Join(l.files, "ok.txt")} {
		f, _, err := d.Open(path)
		if err != nil {
			t.Errorf("Open(%q): %v", path, err)
			continue
		}
		f.Close()
	}
	if _, _, err := d.Open(filepath.Join(l.outside, "secret.txt")); !isDenied(err) {
		t.Errorf("outside through an aliased files_dir: %v", err)
	}
}

func TestOpenRefusesNonRegularFiles(t *testing.T) {
	l := newLayout(t)
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	if _, _, err := d.Open("sub"); !errors.Is(err, agentfs.ErrNotRegular) {
		t.Errorf("directory: %v", err)
	}
	if _, _, err := d.Open("missing.txt"); !errors.Is(err, os.ErrNotExist) || isDenied(err) {
		t.Errorf("missing file: %v", err)
	}
}

func TestOffDirRefusesEverything(t *testing.T) {
	l := newLayout(t)
	for _, d := range []*agentfs.Dir{agentfs.New(""), nil} {
		for _, path := range []string{"ok.txt", filepath.Join(l.files, "ok.txt")} {
			if _, _, err := d.Open(path); !isDenied(err) || !strings.Contains(err.Error(), "files_dir") {
				t.Errorf("Open(%q) on an off Dir: %v", path, err)
			}
			if _, _, err := d.Create(path + ".new"); !isDenied(err) {
				t.Errorf("Create(%q) on an off Dir: %v", path, err)
			}
		}
		if d.Enabled() || d.Path() != "" {
			t.Error("an off Dir reports itself enabled")
		}
	}
}

func TestCreateDeniesEveryEscapeAndWritesNothingOutside(t *testing.T) {
	l := newLayout(t)
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	for _, path := range []string{
		"../outside/new.txt",
		filepath.Join(l.outside, "new.txt"),
		"dir-out/new.txt",
		"dangling-out",
		"link-out",
		"abs-link-out",
		filepath.Join(l.files, "dir-out", "new.txt"),
	} {
		f, _, err := d.Create(path)
		if err == nil {
			f.Close()
			t.Errorf("Create(%q) succeeded", path)
		}
	}
	for _, path := range []string{"../outside/new.txt", "dir-out/new.txt", "dangling-out"} {
		if _, _, err := d.Create(path); err != nil && !isDenied(err) && !errors.Is(err, os.ErrExist) {
			t.Errorf("Create(%q) = %v, want a denial or file exists", path, err)
		}
	}
	entries, _ := os.ReadDir(l.outside)
	if len(entries) != 1 || entries[0].Name() != "secret.txt" {
		t.Errorf("outside/ now holds %v", entries)
	}
	if b, _ := os.ReadFile(filepath.Join(l.outside, "secret.txt")); string(b) != secret {
		t.Errorf("secret was overwritten with %q", b)
	}
}

func TestCreateMakesAnExclusive0600File(t *testing.T) {
	l := newLayout(t)
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	f, where, err := d.Create("sub/new.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("x")
	f.Close()
	if want := filepath.Join(l.files, "sub", "new.bin"); where != want {
		t.Errorf("where = %q, want %q", where, want)
	}
	if info, err := os.Stat(where); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("stat = %v, %v", info, err)
	}
	if _, _, err := d.Create("sub/new.bin"); !errors.Is(err, os.ErrExist) {
		t.Errorf("second Create = %v, want file exists", err)
	}
	if _, _, err := d.Create(filepath.Join(l.files, "sub", "abs.bin")); err != nil {
		t.Errorf("absolute path inside files_dir: %v", err)
	}
	if err := d.Remove("sub/new.bin"); err != nil {
		t.Error(err)
	}
	if err := d.Remove("../outside/secret.txt"); !isDenied(err) {
		t.Errorf("Remove outside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(l.outside, "secret.txt")); err != nil {
		t.Error("Remove deleted a file outside files_dir")
	}
}

// A symlink swapped between a check and the open must never let a read leave
// files_dir. The open is the check here, so every attempt either reads the
// inside file or is refused. A check-then-open implementation fails this test.
func TestSymlinkSwappedWhileOpeningNeverLeaks(t *testing.T) {
	l := newLayout(t)
	inside := filepath.Join(l.files, "real")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "secret.txt"), []byte(inbound), 0o600); err != nil {
		t.Fatal(err)
	}
	swap := filepath.Join(l.files, "swap")
	point := func(target string) {
		tmp := swap + ".tmp"
		os.Remove(tmp)
		if err := os.Symlink(target, tmp); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(tmp, swap); err != nil {
			t.Error(err)
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
			if i%2 == 0 {
				point("../outside")
			} else {
				point("real")
			}
		}
	}()

	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	var read, refused int
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		f, _, err := d.Open("swap/secret.txt")
		if err != nil {
			refused++
			continue
		}
		b, _ := io.ReadAll(f)
		f.Close()
		if string(b) == secret {
			close(stop)
			wg.Wait()
			t.Fatalf("read the outside secret after %d reads and %d refusals", read, refused)
		}
		read++
	}
	close(stop)
	wg.Wait()
	if read == 0 || refused == 0 {
		t.Errorf("the swap never took both states (read %d, refused %d), so the test proved nothing", read, refused)
	}
}
