//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package audit

import (
	"os"

	"golang.org/x/sys/unix"
)

func lock(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			return err
		}
	}
}

func unlock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
