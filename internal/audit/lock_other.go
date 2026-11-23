//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package audit

import "os"

// Without flock, concurrent scopedmail processes can interleave appends and
// break the chain. Run one scopedmail at a time on these platforms.
func lock(*os.File) error   { return nil }
func unlock(*os.File) error { return nil }
