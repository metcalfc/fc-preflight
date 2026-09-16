// Copyright 2026 Fly.io. Apache-2.0.

// Command fc-preflight decides whether a candidate host can run Firecracker
// microVMs the way Fly runs them.
//
// It has two stages. The preflight inspects the host: KVM and the specific
// capabilities Firecracker requires, the CPU, the clocksource, cgroups, the
// syscalls the snapshot and block paths need. The boot stage then actually
// launches Firecracker microVMs and runs a workload inside them, because every
// check in the preflight can pass on a host where that fails.
//
// The output is a human-readable report and, with -json, a machine-readable
// one designed to be diffed against a run on a known-good Fly host.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

const version = "0.1.0"

var (
	flagStage       = flag.String("stage", "preflight", "which stage to run: preflight, boot, or all")
	flagJSON        = flag.String("json", "", "also write the report as JSON to this path (- for stdout)")
	flagVerbose     = flag.Bool("v", false, "stream results and guest console output as they happen")
	flagOffline     = flag.Bool("offline", false, "never use the network; requires -firecracker and -kernel")
	flagFirecracker = flag.String("firecracker", "", "path to a Firecracker binary (default: fetch the pinned release)")
	flagKernel      = flag.String("kernel", "", "path to an uncompressed guest kernel (default: fetch Firecracker's pinned CI kernel)")
	flagCache       = flag.String("cache", "/var/cache/fc-preflight", "where to keep downloaded artifacts")
	flagVMs         = flag.Int("vms", 1, "how many microVMs to boot concurrently in the boot stage")
	flagVCPUs       = flag.Int("vcpus", 2, "vCPUs per microVM")
	flagMemMiB      = flag.Int("mem", 512, "memory per microVM, in MiB")
	flagBootTimeout = flag.Int("boot-timeout", 90, "seconds to wait for a microVM to report and exit")
	flagBootArgs    = flag.String("boot-args", defaultBootArgs, "guest kernel command line")
	flagGuest       = flag.Bool("guest", false, "internal: run as the microVM's init")
)

func main() {
	// Guest mode has to be decided before flags are parsed: as PID 1 inside
	// the microVM this binary is started by the kernel with no arguments at
	// all, and anything it prints before it has mounted /dev goes nowhere.
	if os.Getpid() == 1 || hasArg("-guest") {
		runGuest()
		return
	}

	flag.Usage = usage
	flag.Parse()

	if runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "fc-preflight runs on Linux; this is %s\n", runtime.GOOS)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := NewReport()

	switch *flagStage {
	case "preflight":
		runPreflight(r)
	case "boot":
		runBootStage(ctx, r)
	case "all":
		runPreflight(r)
		// A host that cannot create a VM will not boot one either, and the
		// boot stage's failure would be less informative than the preflight's.
		if hasBlockingKVMFailure(r) {
			r.Addf("boot.skipped", "Boot stage", Skip,
				"skipped: the preflight found a blocking KVM failure, so booting would only "+
					"restate it with less detail")
			break
		}
		runBootStage(ctx, r)
	default:
		fmt.Fprintf(os.Stderr, "unknown -stage %q; want preflight, boot or all\n", *flagStage)
		os.Exit(2)
	}

	r.Finish()
	r.Render(os.Stdout)

	if *flagJSON != "" {
		w := os.Stdout
		if *flagJSON != "-" {
			f, err := os.Create(*flagJSON)
			if err != nil {
				fmt.Fprintf(os.Stderr, "write JSON report: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			w = f
		}
		if err := r.WriteJSON(w); err != nil {
			fmt.Fprintf(os.Stderr, "write JSON report: %v\n", err)
			os.Exit(1)
		}
		if *flagJSON != "-" {
			fmt.Fprintf(os.Stderr, "JSON report written to %s\n", *flagJSON)
		}
	}

	// Exit 1 on any blocking failure, so this can gate a pipeline. Warnings
	// never change the exit code.
	if r.Verdict == Fail {
		os.Exit(1)
	}
}

func hasArg(want string) bool {
	for _, a := range os.Args[1:] {
		if a == want || a == want+"=true" {
			return true
		}
	}
	return false
}

func hasBlockingKVMFailure(r *Report) bool {
	for _, res := range r.Results {
		if res.Status != Fail {
			continue
		}
		switch res.ID {
		case "kvm.device", "kvm.open", "kvm.api_version", "kvm.caps.required",
			"kvm.create_vm", "kvm.create_vcpu", "host.cpu_virt":
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `fc-preflight %s -- can this host run Fly's Firecracker microVMs?

USAGE
  fc-preflight [flags]

STAGES
  -stage preflight   inspect the host only. No root needed for most checks,
                     no network, nothing is launched. Start here.
  -stage boot        launch real Firecracker microVMs and run a workload in
                     them. Needs root (it creates a tap device) and, unless
                     -firecracker and -kernel are given, network access to
                     fetch two pinned, checksum-verified artifacts.
  -stage all         both.

EXAMPLES
  # What most people want first, on a candidate host:
  sudo fc-preflight -stage all -json report.json

  # Air-gapped host, artifacts staged by hand:
  sudo fc-preflight -stage all -offline \
      -firecracker ./firecracker -kernel ./vmlinux

  # Density check: eight microVMs at once.
  sudo fc-preflight -stage boot -vms 8 -v

  # Against Fly's real guest kernel, once you have it:
  sudo fc-preflight -stage boot -kernel ./vmlinux-fly

EXIT STATUS
  0  no blocking failures (warnings may still be present)
  1  at least one blocking failure
  2  bad usage

FLAGS
`, version)
	flag.PrintDefaults()
}
