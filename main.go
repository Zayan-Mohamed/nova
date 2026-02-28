package main

import "github.com/Zayan-Mohamed/nova/cmd"

// These variables are set at link time by GoReleaser via -ldflags.
// They default to "dev" / "none" when building locally with `go build`.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	cmd.Execute()
}
