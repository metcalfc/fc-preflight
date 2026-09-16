# Fly reference guest kernel config

`fly-guest-kernel-6.12.105-fly.config` is the kernel configuration of a live
Fly machine, read from `/proc/config.gz` on 2026-09-15.

## Why it came from /proc and not /boot

A Firecracker guest has no kernel in its filesystem. `/boot` is empty and
`/lib/modules` does not exist, because the kernel is supplied by the host at
boot and every driver it needs is built in (`=y`, never `=m`). So there is no
`/boot/config-*` to read. The kernel is built with `CONFIG_IKCONFIG_PROC`,
which is what makes `/proc/config.gz` available, and that is the only place a
guest's own config can be obtained from.

## What the guest actually uses

The config is a superset: Fly ships one kernel for everything, so it carries
options this machine shape never touches — `CONFIG_PCI`, the whole ACPI tree,
`VIRTIO_PCI`, `VIRTIO_IOMMU`. The machine's real device topology is narrower.
Its `/proc/cmdline`:

```
console=ttyS0 reboot=k panic=1 pci=off acpi=off root=/dev/vda ro
virtio_mmio.device=4K@0xc0001000:6 ... (ten devices, IRQs 6-15)
lapic=notscdeadline random.trust_cpu=on i8042.noaux i8042.nomux i8042.nopnp
```

No PCI bus (`/sys/bus/pci/devices/` is empty), no DMI, no ACPI. Devices are
declared by address on the command line because there is nothing to enumerate
them. Attached: 1 balloon, 7 virtio-blk, 1 virtio-net, 1 vsock. Clocksource
`tsc`, with `kvm-clock` also offered.

## The minimum a guest kernel must have built in

Not modules — there is no initramfs path to load a module for the root disk.

| Option | Why |
| --- | --- |
| `VIRTIO_MMIO` + `VIRTIO_MMIO_CMDLINE_DEVICES` | The whole device model. Without the second, the command-line entries are ignored and the guest has no devices at all. |
| `VIRTIO_BLK` | `root=/dev/vda` |
| `VIRTIO_NET` | networking |
| `VIRTIO_VSOCKETS` / `VSOCKETS` | host↔guest control plane |
| `VIRTIO_BALLOON` | memory reclaim by the host |
| `SERIAL_8250` + `SERIAL_8250_CONSOLE` | `console=ttyS0` is the only console |
| `KVM_GUEST`, `PARAVIRT_CLOCK` | kvm-clock |
| `EXT4_FS`, `OVERLAY_FS` | rootfs and layering |

Not needed: PCI, ACPI, or any real driver bus. The `HYPERVISOR_GUEST` and `PVH`
options are present for other boot protocols, not for this path.

## Host side

This file is about the *guest*. What the machine running the VMM needs is a
different list, and `fc-preflight -stage preflight` checks it directly rather
than by reading a config — see `hostKernelOptions` in `host_linux.go` for the
list and the reason each one is on it.
