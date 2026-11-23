//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package agentfs

import "os"

// linkCount reports 1 where os.FileInfo carries no link count, so the
// hard-link check is skipped there.
func linkCount(os.FileInfo) uint64 { return 1 }
