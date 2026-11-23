//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package agentfs_test

import (
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/momirov/scopedmail/internal/agentfs"
)

func TestOpenRefusesAHardLinkToAFileOutside(t *testing.T) {
	l := newLayout(t)
	if err := os.Link(filepath.Join(l.outside, "secret.txt"), filepath.Join(l.files, "hard.txt")); err != nil {
		t.Fatal(err)
	}
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	f, _, err := d.Open("hard.txt")
	if err == nil {
		b, _ := io.ReadAll(f)
		f.Close()
		t.Fatalf("Open read %q through a hard link", b)
	}
	if !isDenied(err) {
		t.Errorf("Open = %v, want a denial", err)
	}
}

func TestOpenRefusesAFIFOWithoutBlocking(t *testing.T) {
	l := newLayout(t)
	if err := syscall.Mkfifo(filepath.Join(l.files, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	done := make(chan error, 1)
	go func() {
		_, _, err := d.Open("pipe")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Open accepted a FIFO")
		}
	case <-time.After(5 * time.Second):
		unblock(filepath.Join(l.files, "pipe"))
		t.Fatal("Open blocked on a FIFO")
	}
}

// A FIFO swapped in after a path check and before the open would block the
// open until a writer appeared.
func TestFIFOSwappedInWhileOpeningNeverBlocks(t *testing.T) {
	l := newLayout(t)
	reg, fifo, name := filepath.Join(l.files, "r"), filepath.Join(l.files, "p"), filepath.Join(l.files, "x")
	if err := os.WriteFile(reg, []byte(inbound), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	swapped := make(chan struct{})
	go func() {
		defer close(swapped)
		for !stop.Load() {
			os.Rename(reg, name)
			os.Rename(name, reg)
			os.Rename(fifo, name)
			os.Rename(name, fifo)
		}
	}()
	d := agentfs.New(l.files)
	t.Cleanup(func() { d.Close() })
	done := make(chan int, 1)
	go func() {
		opened := 0
		for deadline := time.Now().Add(1500 * time.Millisecond); time.Now().Before(deadline); {
			if f, _, err := d.Open("x"); err == nil {
				opened++
				f.Close()
			}
		}
		done <- opened
	}()
	select {
	case opened := <-done:
		stop.Store(true)
		<-swapped
		if opened == 0 {
			t.Error("the regular file never opened, so the test proved nothing")
		}
	case <-time.After(10 * time.Second):
		stop.Store(true)
		<-swapped
		for _, p := range []string{name, fifo} {
			unblock(p)
		}
		t.Fatal("Open blocked on a FIFO swapped in under it")
	}
}

// unblock opens a FIFO for writing so a reader stuck in open returns.
func unblock(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		f.Close()
	}
}
