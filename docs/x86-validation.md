# Validating fc-preflight on x86_64

The tool has been run end to end on aarch64 (Lima on Apple Silicon, nested).
The x86_64 paths build and vet cleanly but **have never been executed**. This
is the plan to close that.

Read the framing first, because it changes what you are looking at: **this run
is a test of the tool, not of the host.** The host is assumed good. Anything
the tool reports as a problem on a host you believe is fine is a bug in the
tool until proven otherwise, and that is the outcome we are hunting for.

Five of the eight bugs found on the aarch64 run were architecture-specific
checks wearing neutral names, and none of them were visible by reading the
code. Expect more of the same here.

---

## Getting it onto the host

No Go needed on the target. Copy the static binary:

```sh
scp dist/fc-preflight-linux-amd64 you@host:/tmp/fc-preflight
ssh you@host chmod +x /tmp/fc-preflight
```

Verify it arrived intact:

```
006ed4f6a589bdeebfc3b763eddfb203a168f2801b8db2c0927e3ef2bb79a0ef  fc-preflight-linux-amd64
```

The host needs `/dev/kvm`, root, `ip` from iproute2, and outbound HTTPS to
github.com and s3.amazonaws.com for stage two. If it has no egress, see
[Offline](#offline) below.

---

## Run 1 — preflight, and read every line

```sh
sudo /tmp/fc-preflight -stage preflight -json /tmp/pre.json
```

Do not just check the verdict. Read the output against the host you know.

### What must pass, and what it means if it does not

| Check | If this fails on a host you believe is healthy |
| --- | --- |
| `kvm.caps.required` | **Most likely tool bug.** The 14 capability numbers are from `include/uapi/linux/kvm.h` and the list from Firecracker's `arch/x86_64/kvm.rs`. A wrong number reports a present capability as missing. Note *which* capability it names — that is the one to check. |
| `kvm.create_vm` / `kvm.create_vcpu` | These issue real ioctls. Failing here on a working host means the ioctl encoding is wrong for x86. |
| `host.cpu_virt` | Should report `vmx` on Intel or `svm` on AMD. Reporting neither on a host that runs VMs is a tool bug. |
| `host.kernel_config.vendor_kvm` | Should name whichever of `CONFIG_KVM_INTEL` / `CONFIG_KVM_AMD` is set. If it claims both are missing but `/dev/kvm` works, the parse is wrong. |
| `host.tsc.constant_tsc`, `host.tsc.nonstop_tsc` | Any modern server CPU has both. Warnings here are suspicious. |
| `host.clocksource` | Bare metal should read `tsc`. |

### What is *expected* to warn, and is not a bug

- `host.kvm_tuning.nested` — informational either way.
- `host.thp` if set to `always` — a real observation about the host.
- `host.userfaultfd` EPERM if `vm.unprivileged_userfaultfd=0` — common and correct.
- `host.max_map_count` below 262144 — a real observation.
- `host.virt_posture` reporting NESTED **if the host is a VM**. If the host is
  bare metal and it says NESTED, that is a bug. If it is a VM and it says bare
  metal, that is the *same bug we already fixed once on Arm* and I want to know
  immediately.

### Specifically scrutinise

1. **CPU identity line.** Should read like
   `Intel(R) Xeon(R) ... (GenuineIntel family 6 model 106 stepping 6, microcode 0x...)`.
   Any `-` or `unknown` in there means the `/proc/cpuinfo` field mapping is wrong.
2. **`host.kvm_tuning`.** On Intel expect `ept`, on AMD expect `npt`. If either
   is reported *disabled*, check `/sys/module/kvm_{intel,amd}/parameters/` by
   hand before believing it — a hard failure on a false reading would be bad.
3. **`host.io_uring` and `host.userfaultfd`.** These probe raw syscall numbers,
   and `userfaultfd` is **323 on amd64 but 282 on arm64**. If `userfaultfd`
   reports something strange, that number is the first suspect.

---

## Run 2 — boot one microVM

```sh
sudo /tmp/fc-preflight -stage boot -v -json /tmp/boot1.json
```

`-v` streams the guest's console, which is what you want the first time.

This exercises the three things most likely to be wrong on x86:

1. **Artifact extraction.** It downloads `firecracker-v1.17.0-x86_64.tgz` and
   pulls out `release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64`. That member
   path is inferred from the aarch64 archive, which was verified by running it.
   If it errors with `not found in`, the x86 archive lays out differently and
   the fix is one string.
2. **Device enumeration.** Stock Firecracker on x86_64 enumerates virtio
   through ACPI, unlike Fly's guests which use `acpi=off` plus explicit
   `virtio_mmio.device=` args. If `boot.virtio` fails, this is why. That is a
   genuinely interesting finding, not just a tool bug — capture the full
   console output.
3. **The guest binary.** The guest is this same binary packed as `/init`. If
   the console shows the kernel booting and then nothing, the initramfs or the
   x86 guest entry is wrong. The report will include the last 40 console lines.

### Expected shape of a pass

```
[ ok ] boot.launch     1 of 1 microVMs booted, ran the workload and shut down cleanly
[ ok ] boot.virtio     map[virtio0:virtio_blk virtio1:virtio_net]
[ ok ] boot.network    echo RTT ... us; throughput ... Mb/s
[info] boot.perf.clock ... ns per read
```

On bare metal x86, `boot.perf.clock` should be roughly **20–30 ns**. The Arm
nested run gave 38 ns. If you see hundreds of ns on bare metal, something is
reading the clock through a trap and that is worth chasing.

`boot.perf.disk` must be present. If it is missing, the scratch device is not
where the host said it was — the same bug already fixed once, where it
targeted a hardcoded `/dev/vdb`.

---

## Run 3 — concurrency

```sh
sudo /tmp/fc-preflight -stage boot -vms 8 -json /tmp/boot8.json
```

Checks the per-VM tap and `/30` allocation does not collide, and that the
goroutine fan-out reports each VM under its own index. Every VM should boot.
The performance spread widening under contention is expected and is the point.

If some VMs fail and others do not, send the JSON — `boot.raw` has every
guest's full report.

---

## Run 4 — both stages, the way Azure will run it

```sh
sudo /tmp/fc-preflight -stage all -json /tmp/all.json; echo "exit=$?"
```

Exit should be 0 on a healthy host. This is the exact command in the README, so
it is also a check that the documented path works.

---

## Offline

If the host has no egress, stage the artifacts from your laptop:

```sh
curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz
tar xzf firecracker-v1.17.0-x86_64.tgz
curl -LO https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141
scp release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64 vmlinux-6.1.141 you@host:/tmp/
```

```sh
sudo /tmp/fc-preflight -stage all -offline \
    -firecracker /tmp/firecracker-v1.17.0-x86_64 \
    -kernel /tmp/vmlinux-6.1.141 -json /tmp/all.json
```

Note that `-offline` with a supplied binary skips checksum verification, and
the report says so.

---

## What to send back

The four JSON files, plus the console output of run 2 if anything failed.
`/tmp/all.json` alone is enough if everything passed.

The JSON is also the **first x86 reference sample** — the thing an Azure host's
report gets diffed against. Worth keeping regardless of whether it finds a bug.

---

## Cleanup

The tool removes its own tap devices and temp directories. It leaves
`/var/cache/fc-preflight` (about 100 MB of pinned artifacts):

```sh
sudo rm -rf /var/cache/fc-preflight /tmp/fc-preflight /tmp/*.json
```

Nothing else is written, no service is installed, and no host setting is
changed.
