//go:build !windows

package ssm_proxycommand

import (
	"os"
	"syscall"
)

// memProfileSignal triggers a memory profile dump.
//
//nolint:gochecknoglobals
var memProfileSignal os.Signal = syscall.SIGUSR1

// goRoutineDumpSignal triggers a goroutine stack dump.
//
//nolint:gochecknoglobals
var goRoutineDumpSignal os.Signal = syscall.SIGUSR2

// handledSignals are the signals the entrypoint listens for.
//
//nolint:gochecknoglobals
var handledSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, memProfileSignal, goRoutineDumpSignal}
