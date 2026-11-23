//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package agentfs

import (
	"os"
	"syscall"
)

func linkCount(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}
