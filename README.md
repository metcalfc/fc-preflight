# fc-preflight

Decides whether a candidate host can run Firecracker microVMs the way Fly runs
them, and produces a report you can send back to us.

It is one static binary with no dependencies. Nothing is installed, no daemon
is left behind, and the host is not modified: the preflight only reads, and the
boot stage creates a tap device and a temporary directory that it removes when
it exits.

## Quick start

```sh
# On a candidate host:
sudo ./fc-preflight -stage all -json report.json
```

Exit status is 0 if nothing blocking was found and 1 otherwise, so it can gate
a pipeline. Send us `report.json`.

If the host has no outbound network access, stage the two artifacts by hand
(see [Artifacts](#artifacts)) and add `-offline`:

```sh
sudo ./fc-preflight -stage all -offline \
    -firecracker ./firecracker -kernel ./vmlinux -json report.json
```

## The two stages, and why there are two

**`-stage preflight`** inspects the host. It runs in milliseconds, touches
nothing, and needs no network. Most of it works without root.

**`-stage boot`** downloads a pinned Firecracker and a pinned guest kernel,
builds an initramfs, and boots real microVMs that run a workload and report
back over the serial console. It needs root, because giving a microVM a network
interface means creating a tap device.

The split matters because **every check in the preflight can pass on a host
where the boot stage fails.** The preflight is a fast triage that tells you
*why* something is wrong; the boot stage is the actual evidence that it works.
Neither substitutes for the other. `-stage all` runs both, and skips the boot
stage if the preflight already found a blocking KVM failure — at that point
booting would only restate the same finding with less detail.

## What the preflight checks

| Area | What it establishes |
| --- | --- |
| Platform | Distro, kernel version, architecture. Firecracker's floor is 5.10; Fly runs 6.x. |
| Virtualization posture | Bare metal or nested, and if nested, what the outer hypervisor is. Never a failure on its own — see below. |
| CPU | `vmx`/`svm`, `constant_tsc`, `nonstop_tsc`, host clocksource, and the **full CPU flag list**. |
| KVM | `/dev/kvm` opens, `KVM_GET_API_VERSION` is 12, every capability Firecracker requires is present, and a VM and vCPU can actually be created. |
| KVM tuning | `halt_poll_ns`, EPT/NPT, nested, SEV. EPT/NPT disabled is a hard failure. |
| Devices | `/dev/net/tun` for guest networking, `/dev/vhost-vsock` for Fly's in-guest agent. |
| Syscalls | `io_uring` (Firecracker's async block engine), `userfaultfd` (lazy snapshot restore), seccomp-bpf (Firecracker's sandbox). |
| cgroups | v2 unified, with `cpu`, `cpuset`, `memory`, `io`, `pids`. |
| Memory | Overcommit mode, transparent hugepages, `vm.max_map_count`, open-file limit. |
| Host kernel config | Read from `/proc/config.gz` or `/boot/config-$(uname -r)` when available. |

The KVM capability list is not a guess. It is `Kvm::DEFAULT_CAPABILITIES` from
Firecracker's own source (`src/vmm/src/arch/<arch>/kvm.rs`, verified against
v1.17.0) — fourteen capabilities on x86_64, seven on aarch64 — resolved to
their numbers from `include/uapi/linux/kvm.h`. Firecracker checks exactly these
at startup and exits if one is missing. This is the check that separates "KVM
is present" from "KVM is present and Firecracker will run", which on an unusual
host are not the same thing.

### Failure vs warning

A **failure** means a Fly microVM will not work correctly here and no
configuration on our side changes that. A **warning** means it works but
something differs from a Fly host today, usually performance or an unset knob.
Only failures affect the exit code. Every failure carries a remedy; a failure
you cannot act on is a bug in this tool, so tell us.

### Nested virtualization is reported, not rejected

If the host is itself a VM, that is a warning with a loud note, never a
failure. Firecracker runs nested. But a microVM fleet is a workload made
largely of VM exits, and under nesting every guest exit is handled by the outer
hypervisor as well as by KVM here.

Rather than assert a policy about that, the tool measures it. The number to
look at is `boot.perf.clock` — the cost of a single `clock_gettime` inside the
guest. It is the most sensitive cheap signal for nesting, because on a host
whose clocksource is read through the hypervisor instead of straight off the
TSC, every timestamp a guest takes costs an exit, and real workloads take a
great many timestamps. Compare it against the same number from a Fly host
before concluding anything.

## What the boot stage does

It boots one or more real microVMs and runs a workload in each. The guest is
not a distribution image — **it is this same binary**, packed into an
initramfs as `/init`. That is deliberate: the boot stage needs two downloaded
artifacts instead of three, and the code running inside the microVM is code you
can read in this repo rather than whatever a downloaded rootfs happens to start
at boot.

Each microVM gets 2 vCPUs, 512 MiB, a 64 MiB scratch virtio-blk device and its
own tap on its own `/30`. Inside, the guest mounts `/proc`, `/sys` and `/dev`,
then measures:

- which virtio devices it found and which drivers bound to them
- `clock_gettime` cost
- sha256 throughput, single core and across all vCPUs
- memory write bandwidth
- virtio-blk write and read throughput
- a TCP echo round trip and a streaming throughput test against the host, over
  virtio-net

It writes one JSON line to the serial console and resets the VM, which is how
Firecracker is told the run is over. A guest that boots but binds no drivers,
or cannot reach the host, is a failure; the performance numbers are recorded
without an opinion, for comparison.

```sh
sudo ./fc-preflight -stage boot -vms 8 -v    # eight at once, streaming console
```

`-v` streams each guest's console output prefixed with its VM index, which is
what you want when a boot fails. On failure the report includes the last 40
console lines from the guest.

## Artifacts

The boot stage needs a Firecracker binary and an uncompressed guest kernel.
Both are pinned by URL and SHA-256 in `boot_linux.go`, fetched into
`-cache` (default `/var/cache/fc-preflight`), and **verified before anything
executes them**. A checksum mismatch aborts.

| | Source | Pinned |
| --- | --- | --- |
| Firecracker | GitHub release | v1.17.0 |
| Guest kernel | Firecracker's CI bucket | vmlinux-6.1.141 |

`-firecracker` and `-kernel` override either with a local path, which is what
`-offline` requires.

### About the guest kernel

**The pinned kernel is Firecracker's CI kernel, not Fly's.** The boot stage
warns about this every time.

Fly's guest kernel cannot be extracted from a running Fly machine. A Firecracker
guest has no `/boot` and no `/lib/modules` — the kernel is supplied by the host
and every driver is built in, so no part of it exists in the guest filesystem.
It has to come from Fly's infrastructure team.

What we can give you is the **config it is built with**, in
[`reference/fly-guest-kernel-6.12.105-fly.config`](reference/). That is the
`/proc/config.gz` of a live Fly machine — the "`/boot/config` from our reference
image" we promised, obtained the only way it can be. Diff it against the config
of any kernel you plan to boot.

Once you have Fly's actual `vmlinux`, re-run with `-kernel ./vmlinux-fly`. That
is the run that proves the host boots *our* guest, not merely *a* guest.

### A difference worth knowing about

Fly's guests boot with `acpi=off` and an explicit `virtio_mmio.device=`
argument for each device. Stock Firecracker on x86_64 enumerates devices
through ACPI instead. So this tool's default boot line is Firecracker's
documented baseline, not Fly's — passing `acpi=off` to stock Firecracker boots
a guest that finds no devices at all. `-boot-args` overrides it if you want to
experiment. For reference, a real Fly guest's `/proc/cmdline` is:

```
console=ttyS0 reboot=k panic=1 pci=off cgroup_enable=memory swapaccount=1
random.trust_cpu=on i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd acpi=off
lapic=notscdeadline sysctl.kernel.panic_on_rcu_stall=1 quiet
cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 root=/dev/vda ro
virtio_mmio.device=4K@0xc0001000:6  [... one per device ...]
```

## Reading the report

The text report is for a human on the host. The JSON (`-json`) is the one to
send back: it records measurements even where there is nothing to assert,
because the useful comparison is against the same JSON from a known-good Fly
host, not against a threshold baked into this tool.

The CPU flag list is in there for a specific reason. Fly restores snapshots
across hosts, and a snapshot taken where a CPU feature exists and restored
where it does not fails inside the guest as an illegal instruction, long after
the restore reported success. Diffing flag sets is how that gets caught before
it is an incident.

## Testing it on a Mac, with Lima

You do not need a spare Linux box to exercise this. On Apple Silicon **M3 or
later**, Virtualization.framework exposes nested virtualization, so a Lima VM
gets a real `/dev/kvm` and can run Firecracker.

```sh
brew install lima
limactl start --set '.nestedVirtualization=true | .cpus=6 | .memory="8GiB"' \
    --name=fcpf --tty=false template://default

make release
limactl copy dist/fc-preflight-linux-arm64 fcpf:/tmp/fc-preflight
limactl shell fcpf -- sudo /tmp/fc-preflight -stage all -vms 6
```

Or `make lima-up` then `make lima-test`.

This is how the boot stage was developed and verified. Two caveats:

- It is **aarch64**. The x86_64 paths — the fourteen-capability list, the
  `vmx`/`svm` and TSC checks, the amd64 artifacts — are built and vetted but
  have not been run on real x86 KVM.
- It is itself nested, so the tool correctly reports `NESTED` and the numbers
  are not comparable to a bare-metal host. That is useful in its own right: it
  is a live example of the output shape a nested Azure host will produce.

On M1 and M2 there is no nested virtualization and `/dev/kvm` will not appear.

## Building

```sh
make release     # static linux/amd64 and linux/arm64 into dist/, with SHA256SUMS
make check       # gofmt, vet on both arches, tests, build both arches
```

Go 1.22+, standard library only, no module downloads.

The test suite covers the cpio writer, which is the one part that cannot be
checked by running the tool: a malformed initramfs does not make the kernel
complain, it boots a guest with no `/init` and hangs, which looks exactly like
every other way a microVM fails to come up. The tests check the archive
against a real `cpio` rather than against our own reader.

## Status

**Verified end to end.** Built and vetted for linux/amd64 and linux/arm64. On
an aarch64 Linux host with real KVM (Lima on an M5, so itself nested):

- the preflight passes every KVM check, including creating a real VM and vCPU
- the boot stage fetches and checksum-verifies Firecracker v1.17.0 and a guest
  kernel, builds the initramfs, and boots a microVM that mounts its
  filesystems, binds `virtio_blk` and `virtio_net`, runs the full workload,
  reports over the serial console and shuts down cleanly (`exit_code=0`)
- six concurrent microVMs do the same, with the per-VM spread reported

The preflight has also been run on a host with no `/dev/kvm`, where it
correctly identifies the cause — including the case where `CONFIG_KVM=y` but
neither vendor module is built, which passes a naive config check and then has
no device to open.

**Not yet verified:** the x86_64 paths against real x86 KVM, and any run
against Fly's own guest kernel. Both need hardware we did not have; neither is
speculative code, but neither has been executed.

Running it on real hardware taught us things that reading it would not have —
an early version reported an Apple Virtualization guest as bare metal, because
`hypervisor` is an x86-only CPU flag and aarch64 has no equivalent. On an Azure
Arm SKU that would have been exactly the wrong answer. Please send the first
run from a candidate host whatever it says.
