package cli

import (
	"runtime/debug"
	"strings"
)

// Version is set by the release build through -ldflags -X.
var Version string

func versionString() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

// runVersion never reads the config, so it works before setup.
func runVersion(inv *invocation, args []string) error {
	pos, err := parse(newFlagSet("version"), args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("version takes no arguments")
	}
	writeJSON(inv.env.Stdout, map[string]string{"version": versionString()})
	return nil
}
