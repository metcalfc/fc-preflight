// Copyright 2026 Fly.io. Apache-2.0.

//go:build !linux

package main

import (
	"context"
	"fmt"
	"os"
)

// Stubs so the package builds, vets and tests on a developer's machine. The
// tool only does anything on Linux; main refuses to run elsewhere before any
// of these is reached.

const defaultBootArgs = "console=ttyS0 reboot=k panic=1 pci=off"

const guestReportPrefix = "FCPF-REPORT "

func resolveGuestNet(string, int) error { return nil }

func runGuest() {
	fmt.Fprintln(os.Stderr, "fc-preflight guest mode is Linux-only")
	os.Exit(2)
}

func runPreflight(*Report) {
	fmt.Fprintln(os.Stderr, "fc-preflight runs on Linux only")
	os.Exit(2)
}

func runBootStage(context.Context, *Report) {
	fmt.Fprintln(os.Stderr, "fc-preflight runs on Linux only")
	os.Exit(2)
}
