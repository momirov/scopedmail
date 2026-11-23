// Package fsperm refuses files other users could tamper with.
package fsperm

import (
	"fmt"
	"io/fs"
	"runtime"
)

// RejectWritableByOthers fails when info is group- or world-writable, as ssh
// does for its config. Windows has no comparable mode bits, so the check is
// skipped there.
func RejectWritableByOthers(path string, info fs.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		return fmt.Errorf("%s has mode %04o and is writable by group or others; run chmod 600", path, mode)
	}
	return nil
}
