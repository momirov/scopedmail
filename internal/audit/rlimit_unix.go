//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package audit

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sizeMargin is room for the records one invocation appends.
const sizeMargin = 1 << 20

// raiseFileSizeLimit lifts the soft RLIMIT_FSIZE to the hard limit, and
// refuses when the hard limit leaves less than sizeMargin past a log of size
// bytes. The limit is inherited through sudo, so the caller sets it, and at
// the limit an append fails after its action already ran.
func raiseFileSizeLimit(size int64) error {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &lim); err != nil {
		return fmt.Errorf("read file size limit: %w", err)
	}
	if lim.Cur != lim.Max {
		lim.Cur = lim.Max
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &lim); err != nil {
			return fmt.Errorf("raise file size limit: %w", err)
		}
	}
	if uint64(lim.Max) < uint64(size)+sizeMargin {
		return fmt.Errorf("the hard file size limit (ulimit -Hf) is %d bytes, less than %d bytes past the end of the log", uint64(lim.Max), sizeMargin)
	}
	return nil
}
