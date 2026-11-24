package cli_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionFromLdflags(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "scopedmail")
	build := exec.Command("go", "build", "-o", bin,
		"-ldflags", "-X github.com/momirov/scopedmail/internal/cli.Version=9.8.7", "../../cmd/scopedmail")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "--config", "/nonexistent/config.toml", "version").Output()
	if err != nil {
		t.Fatalf("version failed without a config: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != `{"version":"9.8.7"}` {
		t.Fatalf("got %s", got)
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	err := exec.Command(binary, "version", "extra").Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Fatalf("want usage exit 2, got %v", err)
	}
}
