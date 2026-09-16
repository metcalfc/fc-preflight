// Copyright 2026 Fly.io. Apache-2.0.

//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// KVM ioctl numbers. KVMIO is 0xAE and each of these is _IO(KVMIO, n), which
// is (0xAE << 8) | n -- no size or direction bits, so the values are literal.
// From include/uapi/linux/kvm.h.
const (
	kvmGetAPIVersion   = 0xAE00 // _IO(KVMIO, 0x00)
	kvmCreateVM        = 0xAE01 // _IO(KVMIO, 0x01), returns a VM fd
	kvmCheckExtension  = 0xAE03 // _IO(KVMIO, 0x03)
	kvmGetVCPUMmapSize = 0xAE04 // _IO(KVMIO, 0x04)
	kvmCreateVCPU      = 0xAE41 // _IO(KVMIO, 0x41), returns a vCPU fd
)

// kvmStableAPIVersion is the only value KVM has ever reported for a working
// interface. The field exists so a future incompatible KVM can be told apart
// from a broken one; it has been 12 since 2009 and Firecracker refuses
// anything else outright.
const kvmStableAPIVersion = 12

// cap is one KVM_CHECK_EXTENSION capability.
type cap struct {
	num  uintptr
	name string
	// required means Firecracker refuses to start without it, on this arch.
	required bool
	// note explains, for a capability that is not required, why we look.
	note string
}

// Firecracker checks these at startup and exits if any is missing. The lists
// are Kvm::DEFAULT_CAPABILITIES from firecracker/src/vmm/src/arch/<arch>/kvm.rs
// (verified against v1.17.0); the numbers are from include/uapi/linux/kvm.h.
//
// This is the check that most cleanly separates "KVM is present" from "KVM is
// present and Firecracker will actually run", which on a nested or unusual
// host are not the same thing.
var amd64Caps = []cap{
	{0, "KVM_CAP_IRQCHIP", true, ""},
	{3, "KVM_CAP_USER_MEMORY", true, ""},
	{4, "KVM_CAP_SET_TSS_ADDR", true, ""},
	{7, "KVM_CAP_EXT_CPUID", true, ""},
	{14, "KVM_CAP_MP_STATE", true, ""},
	{32, "KVM_CAP_IRQFD", true, ""},
	{33, "KVM_CAP_PIT2", true, ""},
	{35, "KVM_CAP_PIT_STATE2", true, ""},
	{36, "KVM_CAP_IOEVENTFD", true, ""},
	{39, "KVM_CAP_ADJUST_CLOCK", true, ""},
	{41, "KVM_CAP_VCPU_EVENTS", true, ""},
	{50, "KVM_CAP_DEBUGREGS", true, ""},
	{55, "KVM_CAP_XSAVE", true, ""},
	{56, "KVM_CAP_XCRS", true, ""},

	// Not required to boot, but Fly depends on all three in production.
	{136, "KVM_CAP_IMMEDIATE_EXIT", false, "vCPU exit latency; Firecracker uses it to interrupt a running vCPU without a signal round trip"},
	{143, "KVM_CAP_X86_DISABLE_EXITS", false, "lets the host stop trapping HLT/PAUSE/MWAIT, which is a large part of idle microVM cost"},
	{105, "KVM_CAP_CHECK_EXTENSION_VM", false, "per-VM capability queries"},
}

var arm64Caps = []cap{
	{3, "KVM_CAP_USER_MEMORY", true, ""},
	{14, "KVM_CAP_MP_STATE", true, ""},
	{32, "KVM_CAP_IRQFD", true, ""},
	{36, "KVM_CAP_IOEVENTFD", true, ""},
	{70, "KVM_CAP_ONE_REG", true, ""},
	{89, "KVM_CAP_DEVICE_CTRL", true, ""},
	{102, "KVM_CAP_ARM_PSCI_0_2", true, ""},

	{136, "KVM_CAP_IMMEDIATE_EXIT", false, "vCPU exit latency"},
	{165, "KVM_CAP_ARM_VM_IPA_SIZE", false, "guest physical address width; caps how much memory a microVM can be given"},
}

// These report a number rather than a yes/no. They are recorded, not asserted:
// the useful thing is diffing the value against a Fly host.
var sizingCaps = []cap{
	{9, "KVM_CAP_NR_VCPUS", false, "recommended vCPUs per VM"},
	{66, "KVM_CAP_MAX_VCPUS", false, "hard vCPU ceiling per VM"},
	{10, "KVM_CAP_NR_MEMSLOTS", false, "memory slots per VM; Firecracker needs one per memory region"},
}

func ioctl(fd, req, arg uintptr) (uintptr, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg)
	if errno != 0 {
		return r, errno
	}
	return r, nil
}

// checkKVM is the core of the preflight. It does not stop at "/dev/kvm
// exists": it opens it, confirms the API version, queries every capability
// Firecracker requires, and then actually creates a VM and a vCPU. The last
// step is the one that catches a host where KVM is loaded but cannot hand out
// a VM -- which is the normal failure shape on a nested host with
// virtualization disabled at the outer layer.
func checkKVM(r *Report) {
	caps := amd64Caps
	switch runtime.GOARCH {
	case "amd64":
		caps = amd64Caps
	case "arm64":
		caps = arm64Caps
	default:
		r.Fail("kvm.arch", "Supported architecture",
			fmt.Sprintf("this tool knows amd64 and arm64, not %s", runtime.GOARCH),
			"Run on an x86_64 or aarch64 host.")
		return
	}

	fi, err := os.Stat("/dev/kvm")
	if err != nil {
		r.Fail("kvm.device", "/dev/kvm present",
			err.Error(),
			"Load the kvm module for this CPU (modprobe kvm_intel or kvm_amd). On a nested host, "+
				"virtualization must be exposed to this VM by the layer above -- on Azure that means a "+
				"VM size with nested virtualization, or a bare-metal SKU.")
		return
	}
	mode := fi.Mode()
	if mode&os.ModeCharDevice == 0 {
		r.Fail("kvm.device", "/dev/kvm present",
			fmt.Sprintf("/dev/kvm is not a character device (mode %s)", mode),
			"Something has replaced the device node. Expect a char device, major 10.")
		return
	}
	r.Addf("kvm.device", "/dev/kvm present", Pass, "character device, mode %s", mode.Perm())

	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		remedy := "Add the running user to the 'kvm' group, or run as root."
		if os.IsPermission(err) {
			r.Fail("kvm.open", "/dev/kvm openable", fmt.Sprintf("open: %v", err), remedy)
		} else {
			r.Fail("kvm.open", "/dev/kvm openable", fmt.Sprintf("open: %v", err),
				"KVM is present but refused to open. Check dmesg for a kvm module error.")
		}
		return
	}
	defer f.Close()
	kvm := f.Fd()
	r.Addf("kvm.open", "/dev/kvm openable", Pass, "opened O_RDWR as uid %d", os.Geteuid())

	apiVer, err := ioctl(kvm, kvmGetAPIVersion, 0)
	if err != nil {
		r.Fail("kvm.api_version", "KVM API version", fmt.Sprintf("KVM_GET_API_VERSION: %v", err),
			"The device opened but does not speak the KVM ioctl interface.")
		return
	}
	if apiVer != kvmStableAPIVersion {
		r.Fail("kvm.api_version", "KVM API version",
			fmt.Sprintf("KVM_GET_API_VERSION returned %d, want %d", apiVer, kvmStableAPIVersion),
			"Firecracker refuses any value but 12. This kernel's KVM is not ABI-compatible.")
		return
	}
	r.Addf("kvm.api_version", "KVM API version", Pass, "%d", apiVer)

	// Capabilities. A missing required one is reported individually rather
	// than as a single "some capability is missing", because which one is
	// missing is the whole diagnostic.
	missing := []string{}
	present := map[string]int{}
	for _, c := range caps {
		v, err := ioctl(kvm, kvmCheckExtension, c.num)
		if err != nil {
			v = 0
		}
		present[c.name] = int(v)
		switch {
		case v != 0:
			// nothing; rolled up below
		case c.required:
			missing = append(missing, c.name)
		default:
			r.Warn("kvm.cap."+c.name, "KVM capability "+c.name,
				fmt.Sprintf("%s (cap %d) is not supported", c.name, c.num),
				"Not required to boot. "+c.note)
		}
	}
	if len(missing) > 0 {
		r.Fail("kvm.caps.required", "Firecracker-required KVM capabilities",
			fmt.Sprintf("missing: %v", missing),
			"Firecracker checks these at startup and exits. A host kernel this old or this "+
				"restricted cannot run Firecracker regardless of anything else in this report.")
	} else {
		res := Result{
			ID: "kvm.caps.required", Title: "Firecracker-required KVM capabilities",
			Status: Pass,
			Detail: fmt.Sprintf("all %d present", countRequired(caps)),
			Data:   map[string]any{"capabilities": present},
		}
		r.Add(res)
	}

	for _, c := range sizingCaps {
		v, err := ioctl(kvm, kvmCheckExtension, c.num)
		if err != nil {
			continue
		}
		r.Add(Result{ID: "kvm.sizing." + c.name, Title: c.name, Status: Info,
			Detail: fmt.Sprintf("%d (%s)", v, c.note),
			Data:   map[string]any{"value": int(v)}})
	}

	if sz, err := ioctl(kvm, kvmGetVCPUMmapSize, 0); err == nil {
		r.Addf("kvm.vcpu_mmap_size", "vCPU mmap size", Info, "%d bytes", sz)
	}

	// The real test: can this host actually hand out a VM and a vCPU? Every
	// check above can pass on a host where this fails.
	vmfd, err := ioctl(kvm, kvmCreateVM, 0)
	if err != nil {
		r.Fail("kvm.create_vm", "KVM_CREATE_VM",
			fmt.Sprintf("KVM_CREATE_VM: %v", err),
			"KVM answers queries but will not create a VM. This is the usual signature of "+
				"virtualization being present but disabled or already claimed by another hypervisor.")
		return
	}
	defer syscall.Close(int(vmfd))
	r.Addf("kvm.create_vm", "KVM_CREATE_VM", Pass, "created a VM fd")

	vcpufd, err := ioctl(vmfd, kvmCreateVCPU, 0)
	if err != nil {
		r.Fail("kvm.create_vcpu", "KVM_CREATE_VCPU",
			fmt.Sprintf("KVM_CREATE_VCPU: %v", err),
			"A VM was created but no vCPU could be attached to it. Check dmesg for a KVM error.")
		return
	}
	syscall.Close(int(vcpufd))
	r.Addf("kvm.create_vcpu", "KVM_CREATE_VCPU", Pass, "created a vCPU fd")
}

func countRequired(caps []cap) int {
	n := 0
	for _, c := range caps {
		if c.required {
			n++
		}
	}
	return n
}

// probeSyscall reports whether a syscall is available, by making a call that
// is expected to fail with a specific errno if the syscall exists and ENOSYS
// if it does not. It is used for io_uring and userfaultfd, which Firecracker
// and Fly's snapshot path use and which are commonly turned off by hardening.
func probeSyscall(nr uintptr, a1, a2, a3 uintptr) (present bool, errno syscall.Errno) {
	r, _, e := syscall.Syscall(nr, a1, a2, a3)
	if e == syscall.ENOSYS {
		return false, e
	}
	if e == 0 {
		syscall.Close(int(r))
	}
	return true, e
}

var _ = unsafe.Pointer(nil)
