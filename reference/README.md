# Fly reference guest kernel config

**Not in this repo.** Fly's guest kernel configuration is sent to evaluating
partners directly rather than published here. If you are running
`fc-preflight` as part of a host evaluation with Fly, ask your Fly contact for
it; this directory is where to drop it.

## Where it comes from, if you need to regenerate it

A Firecracker guest has no kernel in its filesystem. `/boot` is empty and
`/lib/modules` does not exist, because the kernel is supplied by the host at
boot and every driver it needs is built in (`=y`, never `=m`). So there is no
`/boot/config-*` to read.

Fly's guest kernel is built with `CONFIG_IKCONFIG_PROC`, which makes the
running config available at `/proc/config.gz`. That is the only way to obtain
a guest's own config:

```sh
# On any Fly machine:
zcat /proc/config.gz > fly-guest-kernel.config
```

Note this is also why the boot stage cannot test against Fly's actual kernel
without help: the `vmlinux` itself exists only on the host side and has to come
from Fly's infrastructure team. Pass it with `-kernel` once you have it.

## What a Firecracker guest kernel needs

This part is not Fly-specific and is worth knowing regardless. These must be
built in, not modules — with no initramfs there is no path to load a module for
the root disk.

| Option | Why |
| --- | --- |
| `VIRTIO_MMIO` + `VIRTIO_MMIO_CMDLINE_DEVICES` | The device model, on a guest that discovers devices from the kernel command line rather than through ACPI. Without the second, the command-line entries are ignored and the guest has no devices at all. |
| `VIRTIO_BLK` | the root and scratch disks |
| `VIRTIO_NET` | networking |
| `VIRTIO_VSOCKETS` / `VSOCKETS` | host↔guest control plane. Note the *host* needs nothing for this: Firecracker's vsock is a host-side Unix socket, not `vhost_vsock`. |
| `VIRTIO_BALLOON` | memory reclaim by the host |
| `SERIAL_8250` + `SERIAL_8250_CONSOLE` | `console=ttyS0` is typically the only console |
| `KVM_GUEST`, `PARAVIRT_CLOCK` | kvm-clock |
| `EXT4_FS`, `OVERLAY_FS` | rootfs and layering |

A microVM guest needs neither PCI nor ACPI when devices are declared on the
command line. Options like `HYPERVISOR_GUEST` and `PVH` exist for other boot
protocols and are not part of this path.

## Host side

This file is about the *guest*. What the machine running the VMM needs is a
different list, and `fc-preflight -stage preflight` checks it directly rather
than by reading a config — see `hostKernelOptions` in `host_linux.go` for the
list and the reason each entry is on it.
