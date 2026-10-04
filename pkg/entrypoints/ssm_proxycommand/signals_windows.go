//go:build windows

package ssm_proxycommand

import (
	"os"
	"syscall"
)

// Windows has no SIGUSR1/SIGUSR2, so profile dumps can't be triggered by signal.
// These never match a received signal.
//
//nolint:gochecknoglobals
var (
	memProfileSignal    os.Signal
	goRoutineDumpSignal os.Signal
)

// handledSignals are the signals the entrypoint listens for.
//
//nolint:gochecknoglobals
var handledSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}
