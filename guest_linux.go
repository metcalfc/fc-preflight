// Copyright 2026 Fly.io. Apache-2.0.

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The guest side. This runs as PID 1 inside the microVM, having been packed
// into the initramfs as /init by the host side of the same binary.
//
// Everything it learns is written to the serial console as a single JSON line
// with a sentinel prefix, because the serial console is the only channel that
// is guaranteed to exist: the point of the exercise is partly to find out
// whether the others work.

const guestReportPrefix = "FCPF-REPORT "
const guestLogPrefix = "FCPF-LOG "

// The guest's own network settings arrive on the kernel command line, because
// there is no other channel: the guest has no userland, no DHCP client, and
// the network is the thing being tested. The host side appends these in
// bootOne, one distinct /30 per microVM.
var (
	guestIface = "eth0"
	guestIP    = ""
	guestMask  = "255.255.255.252"
	hostIP     = ""
	guestPort  = echoPort
	guestDisk  = ""
)

// parseGuestCmdline reads the fcpf.* parameters the host appended.
func parseGuestCmdline(cmdline string) {
	for _, field := range strings.Fields(cmdline) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "fcpf.ip":
			guestIP = v
		case "fcpf.mask":
			guestMask = v
		case "fcpf.host":
			hostIP = v
		case "fcpf.iface":
			guestIface = v
		case "fcpf.disk":
			guestDisk = v
		case "fcpf.port":
			if n, err := strconv.Atoi(v); err == nil {
				guestPort = n
			}
		}
	}
}

// GuestReport is what the guest measures. The host asserts on a few fields
// and records the rest for comparison against a Fly host.
type GuestReport struct {
	OK            bool              `json:"ok"`
	Errors        []string          `json:"errors,omitempty"`
	KernelVersion string            `json:"kernel_version"`
	Cmdline       string            `json:"cmdline"`
	CPUs          int               `json:"cpus"`
	MemTotalKB    int64             `json:"mem_total_kb"`
	Clocksource   string            `json:"clocksource"`
	AvailClock    string            `json:"available_clocksource"`
	VirtioDevices map[string]string `json:"virtio_devices"`
	UptimeAtStart float64           `json:"uptime_at_start_s"`

	ClockReadNS   float64 `json:"clock_gettime_ns"`
	CPUHashMBps   float64 `json:"cpu_sha256_mbps_1core"`
	CPUHashMBpsN  float64 `json:"cpu_sha256_mbps_all_cores"`
	MemWriteMBps  float64 `json:"mem_write_mbps"`
	DiskWriteMBps float64 `json:"disk_write_mbps,omitempty"`
	DiskReadMBps  float64 `json:"disk_read_mbps,omitempty"`
	NetEchoRTTus  float64 `json:"net_echo_rtt_us,omitempty"`
	NetThroughput float64 `json:"net_throughput_mbps,omitempty"`
	NetError      string  `json:"net_error,omitempty"`
}

func guestLogf(format string, args ...any) {
	fmt.Printf(guestLogPrefix+format+"\n", args...)
}

// runGuest is the microVM's init. It never returns: it reports, then resets
// the VM, which is how Firecracker is told the run is over.
func runGuest() {
	rep := &GuestReport{VirtioDevices: map[string]string{}}

	// Mount what everything else reads from. devtmpfs gives us the virtio
	// block nodes; without /proc and /sys there is nothing to measure.
	for _, m := range []struct{ src, dst, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"tmpfs", "/tmp", "tmpfs"},
	} {
		if err := syscall.Mount(m.src, m.dst, m.fs, 0, ""); err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("mount %s on %s: %v", m.fs, m.dst, err))
		}
	}

	guestLogf("guest init running, pid %d", os.Getpid())

	rep.UptimeAtStart = readUptime()
	rep.KernelVersion = strings.TrimSpace(readGuestFile("/proc/sys/kernel/osrelease"))
	rep.Cmdline = strings.TrimSpace(readGuestFile("/proc/cmdline"))
	rep.CPUs = runtime.NumCPU()
	rep.MemTotalKB = memTotalKB()
	rep.Clocksource = strings.TrimSpace(readGuestFile("/sys/devices/system/clocksource/clocksource0/current_clocksource"))
	rep.AvailClock = strings.TrimSpace(readGuestFile("/sys/devices/system/clocksource/clocksource0/available_clocksource"))

	// Which virtio devices the guest actually found. This is the check that
	// the device model works end to end: Firecracker put devices on the bus
	// and the guest kernel bound drivers to them.
	if ents, err := os.ReadDir("/sys/bus/virtio/devices"); err == nil {
		for _, e := range ents {
			drv := "(unbound)"
			if l, err := os.Readlink("/sys/bus/virtio/devices/" + e.Name() + "/driver"); err == nil {
				parts := strings.Split(strings.TrimRight(l, "/"), "/")
				drv = parts[len(parts)-1]
			}
			rep.VirtioDevices[e.Name()] = drv
		}
	}
	guestLogf("virtio devices: %v", rep.VirtioDevices)

	rep.ClockReadNS = measureClockRead()
	guestLogf("clock_gettime: %.1f ns/read", rep.ClockReadNS)

	rep.CPUHashMBps = measureHash(1)
	rep.CPUHashMBpsN = measureHash(runtime.NumCPU())
	guestLogf("sha256: %.0f MB/s single core, %.0f MB/s across %d", rep.CPUHashMBps, rep.CPUHashMBpsN, runtime.NumCPU())

	rep.MemWriteMBps = measureMemWrite()
	guestLogf("memory write: %.0f MB/s", rep.MemWriteMBps)

	parseGuestCmdline(rep.Cmdline)

	if w, rd, err := measureDisk(guestDisk); err == nil {
		rep.DiskWriteMBps, rep.DiskReadMBps = w, rd
		guestLogf("disk /dev/vdb: %.0f MB/s write, %.0f MB/s read", w, rd)
	} else {
		guestLogf("disk: skipped (%v)", err)
	}

	switch {
	case guestIP == "" || hostIP == "":
		rep.NetError = "no fcpf.ip/fcpf.host on the kernel command line"
	default:
		if err := configureGuestNet(guestIface, guestIP, guestMask); err != nil {
			rep.NetError = fmt.Sprintf("configure %s: %v", guestIface, err)
		} else if rtt, tput, err := measureNet(hostIP, guestPort); err != nil {
			rep.NetError = err.Error()
		} else {
			rep.NetEchoRTTus, rep.NetThroughput = rtt, tput
			guestLogf("network: %.0f us echo RTT, %.0f Mb/s", rtt, tput)
		}
	}
	if rep.NetError != "" {
		guestLogf("network: FAILED: %s", rep.NetError)
	}

	rep.OK = len(rep.Errors) == 0
	b, _ := json.Marshal(rep)
	fmt.Println(guestReportPrefix + string(b))

	// Give the console a moment to drain before resetting the VM; a reset
	// mid-write loses the report and looks like a guest that never spoke.
	os.Stdout.Sync()
	time.Sleep(200 * time.Millisecond)

	// Firecracker treats a guest reset as shutdown and exits. Nothing below
	// this line runs.
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
	select {}
}

func readGuestFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func readUptime() float64 {
	f := strings.Fields(readGuestFile("/proc/uptime"))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// measureClockRead times clock_gettime(CLOCK_MONOTONIC). This is the most
// telling single number for nested virtualization: on a host whose clocksource
// is read through the hypervisor rather than from the TSC directly, every
// timestamp a guest takes costs a VM exit, and guest workloads take a great
// many timestamps.
func measureClockRead() float64 {
	const n = 200000
	start := time.Now()
	for i := 0; i < n; i++ {
		_ = time.Now()
	}
	return float64(time.Since(start).Nanoseconds()) / n
}

func measureHash(workers int) float64 {
	const chunk = 1 << 20
	const rounds = 64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, chunk)
			h := sha256.New()
			for i := 0; i < rounds; i++ {
				h.Reset()
				h.Write(buf)
				_ = h.Sum(nil)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	return float64(workers*rounds) / elapsed
}

func measureMemWrite() float64 {
	// Sized to stay well inside the guest's memory: this runs in a 512 MiB
	// microVM and an allocation that forces reclaim measures the balloon, not
	// the memory.
	const size = 64 << 20
	const passes = 8

	region := make([]byte, size)

	// Fault the whole region in first, and do not count it. First touch is a
	// page fault per page, which is a different measurement -- mixing the two
	// is what made this report a fifth of the real bandwidth.
	for i := 0; i < len(region); i += 4096 {
		region[i] = 1
	}

	start := time.Now()
	for pass := 0; pass < passes; pass++ {
		for i := range region {
			region[i] = byte(pass)
		}
	}
	elapsed := time.Since(start).Seconds()
	return float64(passes*len(region)) / elapsed / (1 << 20)
}

// measureDisk exercises a virtio-blk device the host attached as a scratch
// drive. It writes with O_DIRECT off but fsyncs, which is what a guest
// workload actually does.
func measureDisk(dev string) (writeMBps, readMBps float64, err error) {
	if dev == "" {
		return 0, 0, fmt.Errorf("no fcpf.disk on the kernel command line")
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	const total = 32 << 20
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i)
	}

	start := time.Now()
	for off := 0; off < total; off += len(buf) {
		if _, err := f.WriteAt(buf, int64(off)); err != nil {
			return 0, 0, err
		}
	}
	if err := f.Sync(); err != nil {
		return 0, 0, err
	}
	writeMBps = float64(total) / time.Since(start).Seconds() / (1 << 20)

	// Drop caches so the read measures the device, not the page cache.
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0o600)

	start = time.Now()
	for off := 0; off < total; off += len(buf) {
		if _, err := f.ReadAt(buf, int64(off)); err != nil {
			return 0, 0, err
		}
	}
	readMBps = float64(total) / time.Since(start).Seconds() / (1 << 20)
	return writeMBps, readMBps, nil
}

// measureNet drives the echo server the host side runs on the tap address.
// The round-trip number is the interesting one: it is a full virtio-net
// round trip through the host's tap, which is the path every Fly guest's
// traffic takes.
func measureNet(host string, port int) (rttUS, throughputMbps float64, err error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var conn net.Conn
	// The host's listener and the guest's boot race; retry briefly.
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err = net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return 0, 0, fmt.Errorf("dial %s: %w", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()

	one := make([]byte, 1)
	const pings = 200
	start := time.Now()
	for i := 0; i < pings; i++ {
		if _, err := conn.Write(one); err != nil {
			return 0, 0, fmt.Errorf("echo write: %w", err)
		}
		if _, err := conn.Read(one); err != nil {
			return 0, 0, fmt.Errorf("echo read: %w", err)
		}
	}
	rttUS = float64(time.Since(start).Microseconds()) / pings

	block := make([]byte, 64<<10)
	const blocks = 512 // 32 MiB
	start = time.Now()
	go func() {
		sink := make([]byte, 64<<10)
		for {
			if _, err := conn.Read(sink); err != nil {
				return
			}
		}
	}()
	for i := 0; i < blocks; i++ {
		if _, err := conn.Write(block); err != nil {
			return rttUS, 0, fmt.Errorf("throughput write: %w", err)
		}
	}
	elapsed := time.Since(start).Seconds()
	throughputMbps = float64(blocks*len(block)) * 8 / elapsed / 1e6
	return rttUS, throughputMbps, nil
}

// Guest interface configuration, by ioctl on a socket. The guest has no
// userland -- no ip(8), no dhcp client -- so the address is set the same way
// those tools set it.
const (
	siocSIFADDR    = 0x8916
	siocSIFNETMASK = 0x891c
	siocGIFFLAGS   = 0x8913
	siocSIFFLAGS   = 0x8914

	iffUp      = 0x1
	iffRunning = 0x40
)

// ifreqAddr matches struct ifreq with a sockaddr_in payload: a 16-byte
// interface name followed by a 24-byte union.
type ifreqAddr struct {
	name [16]byte
	// sockaddr_in: family, port, addr, then 8 bytes of padding, and then the
	// remainder of the ifreq union.
	family uint16
	port   uint16
	addr   [4]byte
	zero   [8]byte
	pad    [8]byte
}

type ifreqFlags struct {
	name  [16]byte
	flags uint16
	pad   [22]byte
}

func configureGuestNet(iface, addr, mask string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	set := func(req uintptr, ip string) error {
		parsed := net.ParseIP(ip).To4()
		if parsed == nil {
			return fmt.Errorf("not an IPv4 address: %q", ip)
		}
		var r ifreqAddr
		copy(r.name[:], iface)
		r.family = syscall.AF_INET
		copy(r.addr[:], parsed)
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req,
			uintptr(unsafe.Pointer(&r))); e != 0 {
			return e
		}
		return nil
	}

	if err := set(siocSIFADDR, addr); err != nil {
		return fmt.Errorf("set address: %w", err)
	}
	if err := set(siocSIFNETMASK, mask); err != nil {
		return fmt.Errorf("set netmask: %w", err)
	}

	var fl ifreqFlags
	copy(fl.name[:], iface)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocGIFFLAGS,
		uintptr(unsafe.Pointer(&fl))); e != 0 {
		return fmt.Errorf("get flags: %w", e)
	}
	fl.flags |= iffUp | iffRunning
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), siocSIFFLAGS,
		uintptr(unsafe.Pointer(&fl))); e != 0 {
		return fmt.Errorf("set flags up: %w", e)
	}
	return nil
}

var _ = binary.BigEndian
