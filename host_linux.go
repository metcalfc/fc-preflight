// Copyright 2026 Fly.io. Apache-2.0.

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Syscall numbers, per architecture. These are probed directly rather than
// inferred from a library, so they have to be right: a wrong number does not
// fail, it calls something else. Verified against the upstream tables
// (arch/x86/entry/syscalls/syscall_64.tbl and asm-generic/unistd.h) -- note
// that userfaultfd differs between the two and io_uring_setup does not.
var syscallNR = map[string]map[string]uintptr{
	"amd64": {"userfaultfd": 323, "io_uring_setup": 425},
	"arm64": {"userfaultfd": 282, "io_uring_setup": 425},
}

func readFileTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readFileDefault(path, def string) string {
	s, err := readFileTrim(path)
	if err != nil {
		return def
	}
	return s
}

// checkPlatform records what this host is. None of it is pass/fail on its own;
// it is the header every other result gets read against, and the part of the
// report that gets diffed against a Fly host.
func checkPlatform(r *Report) {
	uts := syscall.Utsname{}
	_ = syscall.Uname(&uts)

	osrel := map[string]string{}
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if ok {
				osrel[k] = strings.Trim(v, `"`)
			}
		}
		f.Close()
	}

	kernel := readFileDefault("/proc/sys/kernel/osrelease", "unknown")
	r.Add(Result{
		ID: "host.platform", Title: "Host platform", Status: Info,
		Detail: fmt.Sprintf("%s -- kernel %s -- %s",
			osrel["PRETTY_NAME"], kernel, runtime.GOARCH),
		Data: map[string]any{
			"distro": osrel["PRETTY_NAME"], "distro_id": osrel["ID"],
			"version_id": osrel["VERSION_ID"], "kernel": kernel, "arch": runtime.GOARCH,
		},
	})

	// Fly's stated baseline for this evaluation is stock Ubuntu. A different
	// distro is not a failure, but it is the first thing to know when a later
	// check behaves oddly.
	if osrel["ID"] != "ubuntu" {
		r.Warn("host.distro", "Stock Ubuntu",
			fmt.Sprintf("distro is %q, not ubuntu", osrel["ID"]),
			"The evaluation baseline is stock Ubuntu. Results from another distro are still "+
				"useful but are not directly comparable.")
	} else {
		r.Addf("host.distro", "Stock Ubuntu", Pass, "%s", osrel["PRETTY_NAME"])
	}

	// Kernel version. Firecracker supports 5.10+; Fly runs 6.x. Below 5.10 is
	// a hard stop, between 5.10 and 6.1 is worth flagging.
	if maj, min, ok := parseKernelVersion(kernel); ok {
		switch {
		case maj < 5 || (maj == 5 && min < 10):
			r.Fail("host.kernel_version", "Host kernel version",
				fmt.Sprintf("kernel %d.%d is below Firecracker's supported floor of 5.10", maj, min),
				"Use a 5.10+ kernel; Fly hosts run 6.x.")
		case maj == 5:
			r.Warn("host.kernel_version", "Host kernel version",
				fmt.Sprintf("kernel %d.%d is supported by Firecracker but older than Fly's 6.x hosts", maj, min),
				"Prefer a 6.1+ kernel so the comparison against a Fly host is meaningful.")
		default:
			r.Addf("host.kernel_version", "Host kernel version", Pass, "%d.%d", maj, min)
		}
	}
}

func parseKernelVersion(s string) (int, int, bool) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	return maj, min, err1 == nil && err2 == nil
}

// hypervisorDMI maps a DMI vendor or product string to the hypervisor it
// indicates. Used on architectures where there is no CPU flag to ask.
var hypervisorDMI = []struct{ match, name string }{
	{"Microsoft Corporation", "Hyper-V / Azure"},
	{"Apple Virtualization", "Apple Virtualization.framework"},
	{"QEMU", "QEMU/KVM"},
	{"Amazon EC2", "AWS Nitro"},
	{"Google", "Google Compute Engine"},
	{"VMware", "VMware"},
	{"Xen", "Xen"},
	{"KVM", "KVM"},
	{"Bochs", "QEMU/Bochs"},
	{"Parallels", "Parallels"},
	{"innotek", "VirtualBox"},
	{"Alibaba", "Alibaba Cloud"},
}

// detectHypervisor gathers every independent signal that this host is itself a
// guest, and returns the name of the outer hypervisor if any signal fires.
//
// There is no single reliable test. On x86 the 'hypervisor' CPU flag is
// conclusive when present. On aarch64 there is no such flag at all -- which is
// exactly how an early version of this tool reported an Apple Virtualization
// guest as bare metal. So DMI and systemd-detect-virt are consulted on every
// architecture, and any one of them firing is enough.
func detectHypervisor() (nested bool, name string, signals map[string]string) {
	signals = map[string]string{}

	if _, ok := cpuFlags()["hypervisor"]; ok {
		signals["cpu_flag"] = "hypervisor"
		nested = true
	}

	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		v := strings.TrimSpace(string(out))
		signals["systemd_detect_virt"] = v
		if v != "" && v != "none" {
			nested = true
			name = v
		}
	}

	vendor := readFileDefault("/sys/class/dmi/id/sys_vendor", "")
	product := readFileDefault("/sys/class/dmi/id/product_name", "")
	signals["dmi_vendor"] = vendor
	signals["dmi_product"] = product
	for _, h := range hypervisorDMI {
		if strings.Contains(vendor, h.match) || strings.Contains(product, h.match) {
			nested = true
			name = h.name
			break
		}
	}

	if nested && name == "" {
		name = "an unidentified hypervisor"
	}
	return nested, name, signals
}

// checkVirtPosture answers the question the Azure evaluation actually turns
// on: is this bare metal, or a VM? Firecracker runs in both, but nested
// virtualization costs real performance on every VM exit, and a microVM fleet
// is a workload made of VM exits. The check never fails on nested -- it
// reports it loudly, because which one they hand us is the finding.
func checkVirtPosture(r *Report) {
	nested, outer, signals := detectHypervisor()

	data := map[string]any{"nested": nested, "hypervisor": outer}
	for k, v := range signals {
		data[k] = v
	}

	if !nested {
		detail := fmt.Sprintf("bare metal -- no virtualization signal (DMI: %s %s)",
			signals["dmi_vendor"], signals["dmi_product"])
		if runtime.GOARCH != "amd64" {
			// Worth stating: on aarch64 there is no 'hypervisor' CPU flag, so
			// a guest whose host hides its DMI would land here too.
			detail += "; note that aarch64 has no CPU flag for this, so this " +
				"rests on DMI and systemd-detect-virt alone"
		}
		r.Add(Result{ID: "host.virt_posture", Title: "Bare metal or nested", Status: Pass,
			Detail: detail, Data: data})
	} else {
		r.Add(Result{ID: "host.virt_posture", Title: "Bare metal or nested", Status: Warn,
			Detail: fmt.Sprintf("NESTED -- this host is itself a guest of %s (DMI: %s %s)",
				outer, signals["dmi_vendor"], signals["dmi_product"]),
			Data: data,
			Remedy: "Firecracker will run, but every guest VM exit is handled by the outer hypervisor " +
				"as well as by KVM here. Expect materially worse exit-bound latency than a Fly bare-metal " +
				"host. Run the boot stage and compare boot_ms and the workload numbers before drawing " +
				"a conclusion; that is what those measurements are for."})
	}

	checkCPUVirtExtensions(r, nested)
}

// checkCPUVirtExtensions asks whether the CPU can host a VM at all.
//
// This is entirely architecture-specific and does not generalise. On x86 the
// answer is a CPU flag. On aarch64 there is no flag: virtualization is the
// availability of EL2, which the kernel consumes when it brings KVM up, and
// the only honest test is whether KVM itself works -- which the kvm.* checks
// establish by creating a VM and a vCPU. Reporting a missing 'vmx' on aarch64
// is not a conservative check, it is a false failure.
func checkCPUVirtExtensions(r *Report, nested bool) {
	if runtime.GOARCH != "amd64" {
		r.Addf("host.cpu_virt", "CPU virtualization extensions", Info,
			"not a CPU-flag question on %s; virtualization availability is proven by the kvm.* "+
				"checks below, which create a real VM and vCPU", runtime.GOARCH)
		return
	}

	flags := cpuFlags()
	_, vmx := flags["vmx"]
	_, svm := flags["svm"]
	switch {
	case vmx:
		r.Addf("host.cpu_virt", "CPU virtualization extensions", Pass, "vmx (Intel VT-x) present")
	case svm:
		r.Addf("host.cpu_virt", "CPU virtualization extensions", Pass, "svm (AMD-V) present")
	default:
		remedy := "The CPU does not expose virtualization extensions. On bare metal, enable VT-x/AMD-V in firmware."
		if nested {
			remedy = "This is a nested host and the outer hypervisor is not exposing virtualization " +
				"extensions to it. On Azure, use a VM size that supports nested virtualization " +
				"(Dv3/Ev3 and later, or a bare-metal SKU)."
		}
		r.Fail("host.cpu_virt", "CPU virtualization extensions",
			"neither vmx nor svm in /proc/cpuinfo flags", remedy)
	}
}

func cpuFlags() map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "flags" || k == "Features" {
			for _, fl := range strings.Fields(v) {
				out[fl] = struct{}{}
			}
			break // flags are identical across cores
		}
	}
	return out
}

// armImplementers decodes the "CPU implementer" field, which is where an
// aarch64 /proc/cpuinfo puts the vendor. Azure's Arm SKUs are Neoverse, so
// they report as ARM Ltd rather than as Microsoft.
var armImplementers = map[string]string{
	"0x41": "ARM Ltd", "0x42": "Broadcom", "0x43": "Cavium", "0x44": "DEC",
	"0x46": "Fujitsu", "0x48": "HiSilicon", "0x49": "Infineon", "0x4e": "NVIDIA",
	"0x50": "APM", "0x51": "Qualcomm", "0x53": "Samsung", "0x56": "Marvell",
	"0x61": "Apple", "0x66": "Faraday", "0x69": "Intel", "0xc0": "Ampere",
}

// checkCPU records the CPU identity in enough detail to diff against a Fly
// host, and asserts the few properties that Fly's timekeeping depends on.
//
// The full flag list is recorded deliberately. Fly migrates and restores
// snapshots across hosts, and a snapshot taken on a host with a feature the
// destination lacks does not fail at restore time -- it fails later, inside
// the guest, as an illegal instruction. Comparing flag sets is how that gets
// caught before it is a production incident.
func checkCPU(r *Report) {
	id := cpuIdentity()
	flags := cpuFlags()

	sorted := make([]string, 0, len(flags))
	for f := range flags {
		sorted = append(sorted, f)
	}
	sort.Strings(sorted)

	data := map[string]any{"logical_cpus": runtime.NumCPU(), "flags": sorted}
	for k, v := range id {
		data[k] = v
	}

	var desc string
	if runtime.GOARCH == "arm64" {
		impl := id["implementer"]
		vendor := armImplementers[strings.ToLower(impl)]
		if vendor == "" {
			vendor = "implementer " + impl
		}
		data["vendor_name"] = vendor
		desc = fmt.Sprintf("%s part %s rev %s (arch %s), %d logical CPUs",
			vendor, orDash(id["part"]), orDash(id["revision"]),
			orDash(id["architecture"]), runtime.NumCPU())
	} else {
		desc = fmt.Sprintf("%s (%s family %s model %s stepping %s, microcode %s), %d logical CPUs",
			orDash(id["model_name"]), orDash(id["vendor"]), orDash(id["family"]),
			orDash(id["model"]), orDash(id["stepping"]), orDash(id["microcode"]),
			runtime.NumCPU())
	}

	r.Add(Result{ID: "host.cpu", Title: "CPU identity", Status: Info, Detail: desc, Data: data})

	checkTimekeeping(r, flags)
}

// checkTimekeeping asserts that the host has a clock a guest can rely on.
//
// The property Fly needs is the same on both architectures -- a counter that
// ticks at a constant rate, does not stop when the CPU idles, and can be read
// without trapping to the hypervisor -- but how you establish it is not. On
// x86 it is the constant_tsc and nonstop_tsc CPU flags plus a 'tsc'
// clocksource. On aarch64 those flags do not exist: the architected generic
// timer is constant-rate and free-running by specification, and the kernel
// calls it 'arch_sys_counter'. Looking for constant_tsc on aarch64 produces
// two warnings that mean nothing.
func checkTimekeeping(r *Report, flags map[string]struct{}) {
	cur := readFileDefault("/sys/devices/system/clocksource/clocksource0/current_clocksource", "unknown")
	avail := readFileDefault("/sys/devices/system/clocksource/clocksource0/available_clocksource", "unknown")

	switch runtime.GOARCH {
	case "arm64":
		if cur == "arch_sys_counter" {
			r.Addf("host.clocksource", "Host clocksource", Pass,
				"arch_sys_counter -- the architected generic timer, constant-rate and free-running "+
					"by specification (available: %s)", avail)
		} else {
			r.Warn("host.clocksource", "Host clocksource",
				fmt.Sprintf("current clocksource is %q, not arch_sys_counter (available: %s)", cur, avail),
				"On aarch64 the architected generic timer is the clocksource a guest can read cheaply. "+
					"Anything else is read through the hypervisor and costs an exit per timestamp.")
		}
		return
	}

	for _, want := range []struct{ flag, why string }{
		{"constant_tsc", "TSC does not vary with CPU frequency"},
		{"nonstop_tsc", "TSC does not stop in deep C-states"},
	} {
		if _, ok := flags[want.flag]; ok {
			r.Addf("host.tsc."+want.flag, "CPU "+want.flag, Pass, "%s", want.why)
		} else {
			r.Warn("host.tsc."+want.flag, "CPU "+want.flag,
				fmt.Sprintf("%s absent -- %s is not guaranteed", want.flag, want.why),
				"Guest timekeeping relies on a stable TSC. Without this the host must fall back to a "+
					"slower clocksource and guest time can drift across a pause or a snapshot restore.")
		}
	}

	if cur == "tsc" {
		r.Addf("host.clocksource", "Host clocksource", Pass, "tsc (available: %s)", avail)
	} else {
		r.Warn("host.clocksource", "Host clocksource",
			fmt.Sprintf("current clocksource is %q, not tsc (available: %s)", cur, avail),
			"A Fly host runs on tsc. On a nested Azure host this is commonly 'hyperv_clocksource_tsc_page', "+
				"which is slower to read and is a per-read cost paid by every guest. Worth quantifying "+
				"in the boot stage before treating as acceptable.")
	}
}

// cpuIdentity returns the /proc/cpuinfo fields that identify the CPU. The
// field names differ entirely between architectures, so both sets are
// collected under neutral keys.
func cpuIdentity() map[string]string {
	id := map[string]string{}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return id
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		var key string
		switch k {
		// x86
		case "model name":
			key = "model_name"
		case "vendor_id":
			key = "vendor"
		case "cpu family":
			key = "family"
		case "model":
			key = "model"
		case "stepping":
			key = "stepping"
		case "microcode":
			key = "microcode"
		// aarch64
		case "CPU implementer":
			key = "implementer"
		case "CPU architecture":
			key = "architecture"
		case "CPU variant":
			key = "variant"
		case "CPU part":
			key = "part"
		case "CPU revision":
			key = "revision"
		default:
			continue
		}
		if _, seen := id[key]; !seen {
			id[key] = v
		}
	}
	return id
}

// checkKVMTuning reports the KVM module parameters that change microVM
// behaviour at Fly's density. None of them fail the run; all of them are
// things we would want set the same way as a Fly host.
func checkKVMTuning(r *Report) {
	params := []struct{ path, note string }{
		{"/sys/module/kvm/parameters/halt_poll_ns",
			"how long a vCPU spins before yielding on halt; the main idle-latency vs idle-CPU tradeoff"},
		{"/sys/module/kvm_intel/parameters/nested", "nested virt exposed to guests (Fly does not need this)"},
		{"/sys/module/kvm_amd/parameters/nested", "nested virt exposed to guests (Fly does not need this)"},
		{"/sys/module/kvm_intel/parameters/ept", "extended page tables; without it guest memory is unusably slow"},
		{"/sys/module/kvm_amd/parameters/npt", "nested page tables; without it guest memory is unusably slow"},
		{"/sys/module/kvm_intel/parameters/unrestricted_guest", "real-mode guests without emulation"},
		{"/sys/module/kvm_amd/parameters/sev", "AMD SEV availability"},
		{"/sys/module/kvm/parameters/enable_vmware_backdoor", ""},
	}
	found := map[string]string{}
	for _, p := range params {
		v, err := readFileTrim(p.path)
		if err != nil {
			continue
		}
		found[filepath.Base(filepath.Dir(filepath.Dir(p.path)))+"."+filepath.Base(p.path)] = v

		// EPT/NPT are the one pair here worth an opinion: without them, memory
		// virtualization falls back to shadow paging and a microVM fleet is
		// not viable at any density.
		base := filepath.Base(p.path)
		if (base == "ept" || base == "npt") && (v == "N" || v == "0") {
			r.Fail("host.kvm_tuning."+base, "KVM "+strings.ToUpper(base),
				fmt.Sprintf("%s is disabled (%s=%s)", strings.ToUpper(base), p.path, v),
				"Hardware-assisted memory virtualization is off, so KVM falls back to shadow paging. "+
					"Guest memory performance will be an order of magnitude worse. Re-enable it.")
			continue
		}
		if p.note != "" {
			r.Add(Result{ID: "host.kvm_tuning." + base, Title: "KVM parameter " + base, Status: Info,
				Detail: fmt.Sprintf("%s = %s -- %s", p.path, v, p.note)})
		}
	}
	if len(found) == 0 {
		r.Warn("host.kvm_tuning", "KVM module parameters",
			"no /sys/module/kvm*/parameters found",
			"KVM may be built in rather than a module, which is fine, but the tuning knobs could not "+
				"be read and so cannot be compared against a Fly host.")
	}
}

// checkDevices covers the host-side device nodes Firecracker and Fly need
// beyond /dev/kvm: a tap device for guest networking, and vhost-vsock for the
// host/guest control channel that Fly's agent inside every microVM uses.
func checkDevices(r *Report) {
	// /dev/net/tun -- Firecracker's networking is a tap device per microVM.
	if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err == nil {
		f.Close()
		r.Addf("host.tun", "/dev/net/tun openable", Pass, "tap devices can be created")
	} else if os.IsNotExist(err) {
		r.Fail("host.tun", "/dev/net/tun openable", fmt.Sprintf("%v", err),
			"Firecracker gives each microVM a tap device. Load the 'tun' module (modprobe tun).")
	} else {
		r.Warn("host.tun", "/dev/net/tun openable", fmt.Sprintf("%v", err),
			"The node exists but this user cannot open it. Needs CAP_NET_ADMIN; the boot stage runs as root.")
	}

	// vhost-vsock, recorded but deliberately not required.
	//
	// Fly puts an agent in every microVM and reaches it over vsock, so it is
	// tempting to demand the host module. But Firecracker does not use it:
	// its vsock device is implemented inside the VMM and exposed on the host
	// as a Unix domain socket, with only the guest side being virtio-vsock.
	// So a host with no vhost_vsock runs Fly's vsock path perfectly well, and
	// warning about it would send someone chasing a module they do not need.
	if _, err := os.Stat("/dev/vhost-vsock"); err == nil {
		r.Addf("host.vhost_vsock", "/dev/vhost-vsock present", Info,
			"available; note Firecracker does not use it -- its vsock is a host-side Unix socket, "+
				"so this matters only for other VMMs")
	} else {
		r.Addf("host.vhost_vsock", "/dev/vhost-vsock present", Info,
			"absent, which does not affect Firecracker: its vsock device is a host-side Unix "+
				"socket and needs no host kernel module. The guest kernel still needs "+
				"CONFIG_VIRTIO_VSOCKETS, which is a property of the guest image, not of this host")
	}

	// KVM's per-CPU CPUID device makes an exact CPU comparison possible.
	if _, err := os.Stat("/dev/cpu/0/cpuid"); err == nil {
		r.Addf("host.cpuid_dev", "/dev/cpu/0/cpuid present", Info, "raw CPUID readable for exact host comparison")
	}
}

// checkSyscalls probes the syscalls Firecracker and Fly's snapshot path use.
// These are frequently disabled by hardening policy, and the failure mode is
// not a clean error at startup -- it is a feature that silently does not work.
func checkSyscalls(r *Report) {
	nrs, ok := syscallNR[runtime.GOARCH]
	if !ok {
		r.Addf("host.syscalls", "Syscall probes", Skip, "no syscall table for %s", runtime.GOARCH)
		return
	}

	// io_uring: Firecracker's async block engine. Probing with a null params
	// pointer either faults or is rejected -- both mean present -- and creates
	// nothing.
	if _, _, e := syscall.Syscall(nrs["io_uring_setup"], 0, 0, 0); e == syscall.ENOSYS {
		r.Warn("host.io_uring", "io_uring available", "io_uring_setup returns ENOSYS",
			"Firecracker's 'Async' block engine needs io_uring. Without it, fall back to the Sync "+
				"engine -- correct, but with worse block throughput than a Fly host.")
	} else if disabled := readFileDefault("/proc/sys/kernel/io_uring_disabled", "0"); disabled != "0" {
		r.Warn("host.io_uring", "io_uring available",
			fmt.Sprintf("syscall present but kernel.io_uring_disabled = %s", disabled),
			"Set kernel.io_uring_disabled=0, or plan on the Sync block engine.")
	} else {
		r.Addf("host.io_uring", "io_uring available", Pass, "io_uring_setup present and not disabled")
	}

	// userfaultfd: how a snapshot is restored lazily, faulting guest memory in
	// on demand instead of reading it all up front. Fly's resume-from-snapshot
	// latency depends on it.
	const oCloexec = 0x80000
	fd, _, e := syscall.Syscall(nrs["userfaultfd"], oCloexec, 0, 0)
	switch {
	case e == syscall.ENOSYS:
		r.Warn("host.userfaultfd", "userfaultfd available", "userfaultfd returns ENOSYS",
			"This kernel lacks CONFIG_USERFAULTFD. Lazy snapshot restore is not possible; restores "+
				"must page in the whole guest memory up front.")
	case e == syscall.EPERM:
		unpriv := readFileDefault("/proc/sys/vm/unprivileged_userfaultfd", "?")
		r.Warn("host.userfaultfd", "userfaultfd available",
			fmt.Sprintf("userfaultfd returns EPERM (vm.unprivileged_userfaultfd = %s)", unpriv),
			"Present but restricted to CAP_SYS_PTRACE. That is workable if the VMM runs privileged; "+
				"otherwise set vm.unprivileged_userfaultfd=1.")
	case e != 0:
		r.Addf("host.userfaultfd", "userfaultfd available", Warn, "userfaultfd: %v", e)
	default:
		syscall.Close(int(fd))
		r.Addf("host.userfaultfd", "userfaultfd available", Pass, "created and closed a userfaultfd")
	}

	// seccomp: Firecracker installs a seccomp-bpf filter on every thread as
	// its primary sandbox. Without it Firecracker still runs, but without the
	// isolation property that makes it acceptable to run untrusted guests.
	status := readFileDefault("/proc/self/status", "")
	if strings.Contains(status, "Seccomp:") {
		r.Addf("host.seccomp", "seccomp-bpf available", Pass, "kernel reports per-thread seccomp state")
	} else {
		r.Fail("host.seccomp", "seccomp-bpf available", "no Seccomp field in /proc/self/status",
			"Firecracker's sandbox is a seccomp-bpf filter. Needs CONFIG_SECCOMP_FILTER.")
	}
}

// checkCgroups. Fly bounds every microVM's CPU and memory with cgroup v2;
// Firecracker's jailer places the process into a cgroup at startup.
func checkCgroups(r *Report) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &st); err != nil {
		r.Fail("host.cgroups", "cgroup v2 unified hierarchy", fmt.Sprintf("statfs /sys/fs/cgroup: %v", err),
			"Mount the unified cgroup hierarchy at /sys/fs/cgroup.")
		return
	}
	const cgroup2SuperMagic = 0x63677270
	if st.Type != cgroup2SuperMagic {
		r.Warn("host.cgroups", "cgroup v2 unified hierarchy",
			fmt.Sprintf("/sys/fs/cgroup is not cgroup2 (fs magic 0x%x)", st.Type),
			"Fly uses cgroup v2 exclusively. Boot with systemd.unified_cgroup_hierarchy=1.")
		return
	}
	ctrls := readFileDefault("/sys/fs/cgroup/cgroup.controllers", "")
	have := map[string]bool{}
	for _, c := range strings.Fields(ctrls) {
		have[c] = true
	}
	var missing []string
	for _, want := range []string{"cpu", "cpuset", "memory", "io", "pids"} {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		r.Warn("host.cgroups", "cgroup v2 unified hierarchy",
			fmt.Sprintf("cgroup2 mounted but controllers missing: %v (have: %s)", missing, ctrls),
			"Fly bounds each microVM's cpu, memory and io. Enable the missing controllers.")
		return
	}
	r.Addf("host.cgroups", "cgroup v2 unified hierarchy", Pass, "controllers: %s", ctrls)
}

// checkMemory covers the memory settings that matter at microVM density:
// overcommit, transparent hugepages, and the map-count ceiling.
func checkMemory(r *Report) {
	total := memTotalKB()
	r.Add(Result{ID: "host.memory", Title: "Host memory", Status: Info,
		Detail: fmt.Sprintf("%.1f GiB total", float64(total)/(1024*1024)),
		Data:   map[string]any{"mem_total_kb": total}})

	overcommit := readFileDefault("/proc/sys/vm/overcommit_memory", "?")
	if overcommit == "2" {
		r.Warn("host.overcommit", "Memory overcommit",
			"vm.overcommit_memory = 2 (strict)",
			"Firecracker allocates a guest's full memory as an anonymous mapping and relies on it "+
				"being lazily backed. Strict overcommit accounting will cap density far below a Fly host.")
	} else {
		r.Addf("host.overcommit", "Memory overcommit", Pass, "vm.overcommit_memory = %s", overcommit)
	}

	thp := readFileDefault("/sys/kernel/mm/transparent_hugepage/enabled", "")
	if thp != "" {
		st := Info
		remedy := ""
		if strings.Contains(thp, "[always]") {
			st = Warn
			remedy = "THP set to 'always' inflates each microVM's resident memory and interacts badly " +
				"with balloon-driven reclaim. Fly runs 'madvise'."
		}
		r.Add(Result{ID: "host.thp", Title: "Transparent hugepages", Status: st,
			Detail: fmt.Sprintf("%s", thp), Remedy: remedy})
	}

	maxMap := readFileDefault("/proc/sys/vm/max_map_count", "?")
	if n, err := strconv.Atoi(maxMap); err == nil && n < 262144 {
		r.Warn("host.max_map_count", "vm.max_map_count",
			fmt.Sprintf("vm.max_map_count = %d", n),
			"Low for a host running many VMMs at once. Fly hosts run 262144 or more.")
	} else {
		r.Addf("host.max_map_count", "vm.max_map_count", Pass, "%s", maxMap)
	}

	// File descriptors. Each microVM costs a VMM process several fds, and the
	// ceiling is reached quietly.
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		st := Pass
		remedy := ""
		if lim.Cur < 65536 {
			st = Warn
			remedy = "Raise the open-file limit before running a dense microVM fleet."
		}
		r.Add(Result{ID: "host.nofile", Title: "Open file limit", Status: st,
			Detail: fmt.Sprintf("soft %d, hard %d", lim.Cur, lim.Max), Remedy: remedy})
	}
}

func memTotalKB() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "MemTotal:") {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 {
				n, _ := strconv.ParseInt(fields[1], 10, 64)
				return n
			}
		}
	}
	return 0
}

// hostKernelOptions are the host-side kernel config options Firecracker and
// Fly need. This is the host counterpart to the guest config shipped in
// reference/ -- the guest config says what a microVM's kernel must have, this
// says what the machine running the VMM must have.
var hostKernelOptions = []struct {
	opt      string
	required bool
	why      string
}{
	{"CONFIG_KVM", true, "the hypervisor itself"},
	{"CONFIG_TUN", true, "tap devices for guest networking"},
	{"CONFIG_SECCOMP_FILTER", true, "Firecracker's sandbox"},
	{"CONFIG_CGROUPS", true, "resource bounding per microVM"},
	{"CONFIG_MEMCG", true, "memory bounding per microVM"},
	{"CONFIG_CPUSETS", true, "pinning microVMs to cores"},
	{"CONFIG_NET_NS", true, "network namespace per microVM (the jailer)"},
	{"CONFIG_PID_NS", true, "pid namespace per microVM (the jailer)"},
	{"CONFIG_EVENTFD", true, "ioeventfd/irqfd plumbing"},
	// Not CONFIG_VHOST_VSOCK: Firecracker's vsock is a host-side Unix socket
	// and needs no host module. The guest kernel needs CONFIG_VIRTIO_VSOCKETS,
	// which is a property of the guest image -- see reference/.
	{"CONFIG_USERFAULTFD", false, "lazy snapshot restore"},
	{"CONFIG_IO_URING", false, "Firecracker's async block engine"},
	{"CONFIG_TRANSPARENT_HUGEPAGE", false, "guest memory backing"},
	{"CONFIG_KSM", false, "same-page merging across microVMs; optional density lever"},
	{"CONFIG_USER_NS", false, "unprivileged jailer configurations"},
	{"CONFIG_NF_TABLES", false, "guest egress NAT"},
}

// checkHostKernelConfig reads the running kernel's config, if the host exposes
// it. Many stock kernels do not, so absence is a skip rather than a failure --
// the syscall and device probes above are the authoritative checks, and this
// one only explains *why* one of them failed.
func checkHostKernelConfig(r *Report) {
	cfg, src, err := readKernelConfig()
	if err != nil {
		r.Addf("host.kernel_config", "Host kernel config", Skip,
			"not readable (%v); the direct probes above are authoritative", err)
		return
	}

	var missingReq, missingOpt []string
	for _, o := range hostKernelOptions {
		v, ok := cfg[o.opt]
		if ok && (v == "y" || v == "m") {
			continue
		}
		if o.required {
			missingReq = append(missingReq, fmt.Sprintf("%s (%s)", o.opt, o.why))
		} else {
			missingOpt = append(missingOpt, fmt.Sprintf("%s (%s)", o.opt, o.why))
		}
	}

	// On x86 the generic CONFIG_KVM does not by itself give you a hypervisor:
	// /dev/kvm appears only when the per-vendor module is present too. A
	// kernel with CONFIG_KVM=y and neither of these is exactly the shape that
	// passes a config check and then has no /dev/kvm to open.
	if runtime.GOARCH == "amd64" {
		intel := cfg["CONFIG_KVM_INTEL"]
		amd := cfg["CONFIG_KVM_AMD"]
		hasIntel := intel == "y" || intel == "m"
		hasAMD := amd == "y" || amd == "m"
		if !hasIntel && !hasAMD {
			missingReq = append(missingReq,
				"CONFIG_KVM_INTEL or CONFIG_KVM_AMD (the per-vendor KVM module; CONFIG_KVM alone creates no /dev/kvm)")
		} else {
			r.Addf("host.kernel_config.vendor_kvm", "Per-vendor KVM module", Pass,
				"CONFIG_KVM_INTEL=%s CONFIG_KVM_AMD=%s", orDash(intel), orDash(amd))
		}
	}

	if len(missingReq) > 0 {
		r.Fail("host.kernel_config", "Host kernel config",
			fmt.Sprintf("from %s, missing required: %s", src, strings.Join(missingReq, ", ")),
			"Rebuild or replace the host kernel with these enabled.")
	} else {
		r.Addf("host.kernel_config", "Host kernel config", Pass,
			"from %s, all %d required options present", src, countRequiredOpts())
	}
	if len(missingOpt) > 0 {
		r.Warn("host.kernel_config.optional", "Host kernel config (optional)",
			fmt.Sprintf("absent: %s", strings.Join(missingOpt, ", ")),
			"None of these stop a microVM booting. Each one Fly has and this host does not is a "+
				"capability Fly would be giving up.")
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func countRequiredOpts() int {
	n := 0
	for _, o := range hostKernelOptions {
		if o.required {
			n++
		}
	}
	return n
}

// readKernelConfig returns the running kernel's config as a map of option to
// value ("y", "m" or a literal), from /proc/config.gz if the kernel was built
// with CONFIG_IKCONFIG_PROC, else from /boot/config-$(uname -r).
//
// Note for anyone reading this alongside the reference guest config: a
// Firecracker guest has no /boot at all -- the kernel comes from the host, not
// from the guest filesystem -- so /proc/config.gz is the only way to get a
// guest's config. That is how reference/ was produced.
func readKernelConfig() (map[string]string, string, error) {
	if b, err := os.ReadFile("/proc/config.gz"); err == nil {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err == nil {
			defer zr.Close()
			m, err := parseKernelConfig(zr)
			return m, "/proc/config.gz", err
		}
	}
	rel := readFileDefault("/proc/sys/kernel/osrelease", "")
	path := "/boot/config-" + rel
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("no /proc/config.gz and no %s", path)
	}
	defer f.Close()
	m, err := parseKernelConfig(f)
	return m, path, err
}

func parseKernelConfig(rd interface{ Read([]byte) (int, error) }) (map[string]string, error) {
	cfg := map[string]string{}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cfg[k] = strings.Trim(v, `"`)
	}
	return cfg, sc.Err()
}

// runPreflight runs every host check. Order is deliberate: platform and virt
// posture first, so that everything after is read in context.
func runPreflight(r *Report) {
	checkPlatform(r)
	checkVirtPosture(r)
	checkCPU(r)
	checkKVM(r)
	checkKVMTuning(r)
	checkDevices(r)
	checkSyscalls(r)
	checkCgroups(r)
	checkMemory(r)
	checkHostKernelConfig(r)
}
