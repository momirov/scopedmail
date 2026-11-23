//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package audit

func raiseFileSizeLimit(int64) error { return nil }
