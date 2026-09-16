// Copyright 2026 Fly.io. Apache-2.0.

//go:build linux

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Stage two: actually boot a Firecracker microVM and run a workload in it.
//
// Everything in the preflight can pass on a host where this fails, which is
// the reason this stage exists. It is also where the numbers worth comparing
// against a Fly host come from -- a pass/fail on KVM capabilities says the
// host can run Firecracker, and says nothing about whether it runs it well.

// Pinned artifacts. Both are fetched over HTTPS and checked against these
// digests before anything executes them; a mismatch aborts. The checksums were
// taken from the published release (Firecracker) and computed from the
// download (kernel) on 2026-09-15.
type artifact struct {
	url    string
	sha256 string
	// member, for a tarball, is the path inside it to extract.
	member string
}

const firecrackerVersion = "v1.17.0"

var firecrackerArtifacts = map[string]artifact{
	"amd64": {
		url:    "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz",
		sha256: "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
		member: "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64",
	},
	"arm64": {
		url:    "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-aarch64.tgz",
		sha256: "e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256",
		member: "release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64",
	},
}

// The guest kernel for the boot test, from Firecracker's own CI bucket.
//
// This is NOT Fly's kernel. Fly's guest kernel is supplied by the host and
// does not exist inside a guest filesystem, so it cannot be extracted from a
// running Fly machine -- it has to come from Fly's infrastructure team. The
// config it is built with is in reference/, and -kernel swaps the real one in
// once it is available. See the README.
var guestKernelArtifacts = map[string]artifact{
	"amd64": {
		url:    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/x86_64/vmlinux-6.1.141",
		sha256: "b36a4a1b10f33b9cfdcde3d1a787d9c090556a3edb211cd06d1f3f9a6c7e8724",
	},
	"arm64": {
		url:    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.13/aarch64/vmlinux-6.1.141",
		sha256: "69aa3308219ec1a070bc9a8e7f80c3b34056fed8ae05efb44e55f73b31adde44",
	},
}

// Guest networking. Each microVM gets its own /30 and its own tap, so the
// -vms flag can run several at once without them sharing a subnet.
const (
	tapPrefix = "fcpf"
	echoPort  = 52345
)

// Each microVM gets a /30 carved out of -guest-net: .1 is the host end of the
// tap, .2 is the guest. The range is a flag because every private range is
// something somebody's firewall drops, and being able to move is cheaper than
// arguing with a policy.
func vmBase(i int) uint32 { return guestNetBase + uint32(i)*4 }

func ipString(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func vmHostIP(i int) string  { return ipString(vmBase(i) + 1) }
func vmGuestIP(i int) string { return ipString(vmBase(i) + 2) }
func vmTap(i int) string     { return fmt.Sprintf("%s%d", tapPrefix, i) }
func vmMAC(i int) string {
	b := vmBase(i) + 2
	return fmt.Sprintf("06:00:%02X:%02X:%02X:%02X", byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
}

const guestNetmask = "255.255.255.252"

// guestNetBase is the first address of -guest-net, resolved at startup.
var guestNetBase uint32

// resolveGuestNet parses -guest-net and checks it is big enough for -vms.
func resolveGuestNet(cidr string, vms int) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("-guest-net %q: %w", cidr, err)
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("-guest-net %q: must be IPv4", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	if avail := 1 << (bits - ones) / 4; avail < vms {
		return fmt.Errorf("-guest-net %s holds %d /30s but -vms is %d", cidr, avail, vms)
	}
	base := ipnet.IP.To4()
	guestNetBase = uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	return nil
}

// defaultBootArgs is the Firecracker-documented baseline, not Fly's.
//
// Fly's own guests boot with acpi=off and an explicit virtio_mmio.device=
// argument per device. Stock Firecracker on x86_64 enumerates devices through
// ACPI instead, so passing acpi=off here would boot a guest that finds no
// devices at all. The difference is worth knowing about but is not something
// to reproduce in a portability test; -boot-args overrides if you want to.
const defaultBootArgs = "console=ttyS0 reboot=k panic=1 pci=off"

// consoleTailLines is how much of the guest's console to keep for a failure
// report. It was 40, which was not enough: a guest that panics prints a stack
// trace, and the line that says *why* -- the initramfs unpack result, or the
// exec failure -- scrolls off the top before the panic ends.
const consoleTailLines = 120

// elfInterpreter reports the ELF interpreter a binary requires, if any. A
// binary with no PT_INTERP segment is statically linked.
func elfInterpreter(path string) (interp string, dynamic bool, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		buf, err := io.ReadAll(p.Open())
		if err != nil {
			return "", true, nil // it has one; we just could not read it
		}
		return strings.TrimRight(string(buf), "\x00"), true, nil
	}
	return "", false, nil
}

// diagnoseConsole turns a guest that died into a sentence, for the failures
// whose console signature we recognise. Without this the report hands over a
// kernel stack trace and leaves the reader to know that ENOENT on init means
// a missing ELF interpreter rather than a missing file.
func diagnoseConsole(lines []string) string {
	joined := strings.Join(lines, "\n")
	switch {
	case strings.Contains(joined, "Failed to execute /init (error -2)"):
		return "The kernel booted, found /init and could not exec it (ENOENT). For a static " +
			"binary that means the file is absent; for a dynamic one it means its interpreter " +
			"is, and the guest has no libc. Check boot.initramfs.linkage above."
	case strings.Contains(joined, "Initramfs unpacking failed"):
		return "The kernel rejected the initramfs archive, so the guest root filesystem is empty. " +
			"This is a bug in this tool's cpio writer, not in the host -- please report the " +
			"console output."
	case strings.Contains(joined, "No working init found"):
		return "The guest root filesystem came up empty. Either the initramfs did not unpack or " +
			"/init is not in it."
	case strings.Contains(joined, "Kernel panic"):
		return "The guest kernel panicked. The console tail above is the whole of what it said."
	}
	return ""
}

// resolveArtifact returns a local path to a pinned artifact, downloading it
// into the cache directory if it is not already there and verifying the digest
// either way.
func resolveArtifact(ctx context.Context, cacheDir, name string, a artifact) (string, error) {
	dest := filepath.Join(cacheDir, name)
	if ok, _ := fileHasDigest(dest, a.sha256); ok {
		return dest, nil
	}
	if *flagOffline {
		return "", fmt.Errorf("%s not in cache at %s and -offline is set; supply it with a flag", name, dest)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "fetching %s ...\n", a.url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", a.url, resp.Status)
	}

	tmp := dest + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	f.Close()

	got := hex.EncodeToString(h.Sum(nil))
	if got != a.sha256 {
		os.Remove(tmp)
		return "", fmt.Errorf("checksum mismatch for %s:\n  want %s\n  got  %s", a.url, a.sha256, got)
	}

	if a.member != "" {
		extracted, err := extractFromTarGz(tmp, a.member, dest)
		os.Remove(tmp)
		if err != nil {
			return "", err
		}
		return extracted, nil
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	return dest, nil
}

func fileHasDigest(path, want string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == want, nil
}

// extractFromTarGz pulls one member out of a tarball. Note that the digest was
// verified on the tarball, before this ran -- the extracted member is not
// separately pinned, because the archive it came from is.
func extractFromTarGz(archive, member, dest string) (string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("%s not found in %s", member, archive)
		}
		if err != nil {
			return "", err
		}
		if hdr.Name != member {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		defer out.Close()
		if _, err := io.Copy(out, tr); err != nil {
			return "", err
		}
		return dest, nil
	}
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setupTap creates and addresses the host side of one microVM's network.
func setupTap(ctx context.Context, i int) error {
	tap := vmTap(i)
	_ = run(ctx, "ip", "link", "del", tap) // ignore: usually absent
	if err := run(ctx, "ip", "tuntap", "add", "dev", tap, "mode", "tap"); err != nil {
		return err
	}
	if err := run(ctx, "ip", "addr", "add", vmHostIP(i)+"/30", "dev", tap); err != nil {
		return err
	}
	return run(ctx, "ip", "link", "set", "dev", tap, "up")
}

func teardownTap(tap string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = run(ctx, "ip", "link", "del", tap)
}

// echoServer answers the guest's network measurement. It is a plain TCP echo:
// the guest times a round trip on it and then streams at it.
func echoServer(ctx context.Context, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln, nil
}

type vmOutcome struct {
	Index    int          `json:"index"`
	BootMS   float64      `json:"boot_ms"`
	TotalMS  float64      `json:"total_ms"`
	Guest    *GuestReport `json:"guest,omitempty"`
	Err      string       `json:"error,omitempty"`
	Console  []string     `json:"console_tail,omitempty"`
	ExitCode int          `json:"exit_code"`
}

// bootOne runs a single microVM end to end and returns what the guest said.
func bootOne(ctx context.Context, i int, fcBin, kernel, initramfs, workDir string) vmOutcome {
	out := vmOutcome{Index: i}
	start := time.Now()

	if err := setupTap(ctx, i); err != nil {
		out.Err = fmt.Sprintf("tap setup: %v", err)
		return out
	}
	defer teardownTap(vmTap(i))

	echoCtx, cancelEcho := context.WithCancel(ctx)
	defer cancelEcho()
	if _, err := echoServer(echoCtx, net.JoinHostPort(vmHostIP(i), strconv.Itoa(echoPort))); err != nil {
		out.Err = fmt.Sprintf("echo server: %v", err)
		return out
	}

	// A scratch drive, so the guest has a virtio-blk device to measure.
	scratch := filepath.Join(workDir, fmt.Sprintf("scratch%d.img", i))
	sf, err := os.Create(scratch)
	if err != nil {
		out.Err = fmt.Sprintf("scratch disk: %v", err)
		return out
	}
	if err := sf.Truncate(64 << 20); err != nil {
		sf.Close()
		out.Err = fmt.Sprintf("scratch disk truncate: %v", err)
		return out
	}
	sf.Close()
	defer os.Remove(scratch)

	// The scratch drive is the only block device attached and there is no root
	// device, so the guest sees it as /dev/vda. Telling it rather than letting
	// it guess means adding a rootfs later does not silently move the target.
	bootArgs := fmt.Sprintf("%s fcpf.ip=%s fcpf.mask=%s fcpf.host=%s fcpf.port=%d fcpf.disk=%s",
		*flagBootArgs, vmGuestIP(i), guestNetmask, vmHostIP(i), echoPort, "/dev/vda")

	cfg := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": kernel,
			"initrd_path":       initramfs,
			"boot_args":         bootArgs,
		},
		"drives": []any{map[string]any{
			"drive_id":       "scratch",
			"path_on_host":   scratch,
			"is_root_device": false,
			"is_read_only":   false,
		}},
		"machine-config": map[string]any{
			"vcpu_count":   *flagVCPUs,
			"mem_size_mib": *flagMemMiB,
			"smt":          false,
		},
		"network-interfaces": []any{map[string]any{
			"iface_id":      "eth0",
			"host_dev_name": vmTap(i),
			"guest_mac":     vmMAC(i),
		}},
	}
	cfgPath := filepath.Join(workDir, fmt.Sprintf("config%d.json", i))
	cfgBytes, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		out.Err = fmt.Sprintf("write config: %v", err)
		return out
	}

	vmCtx, cancel := context.WithTimeout(ctx, time.Duration(*flagBootTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(vmCtx, fcBin, "--no-api", "--config-file", cfgPath)
	cmd.Stdin = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		out.Err = fmt.Sprintf("stdout pipe: %v", err)
		return out
	}
	cmd.Stderr = os.Stderr

	launch := time.Now()
	if err := cmd.Start(); err != nil {
		out.Err = fmt.Sprintf("start firecracker: %v", err)
		return out
	}

	var tail []string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(tail) >= consoleTailLines {
			tail = tail[1:]
		}
		tail = append(tail, line)

		if *flagVerbose {
			fmt.Fprintf(os.Stderr, "  vm%d| %s\n", i, line)
		}
		switch {
		case strings.Contains(line, guestReportPrefix):
			_, payload, _ := strings.Cut(line, guestReportPrefix)
			var gr GuestReport
			if err := json.Unmarshal([]byte(strings.TrimSpace(payload)), &gr); err != nil {
				out.Err = fmt.Sprintf("parse guest report: %v", err)
			} else {
				out.Guest = &gr
				out.BootMS = gr.UptimeAtStart * 1000
			}
		case strings.Contains(line, guestLogPrefix) && out.BootMS == 0:
			// first sign of life from the guest
		}
	}
	err = cmd.Wait()
	out.TotalMS = float64(time.Since(launch).Microseconds()) / 1000
	out.Console = tail
	if ee, ok := err.(*exec.ExitError); ok {
		out.ExitCode = ee.ExitCode()
	}

	if out.Guest == nil && out.Err == "" {
		reason := "guest produced no report"
		if vmCtx.Err() == context.DeadlineExceeded {
			reason = fmt.Sprintf("timed out after %ds with no report from the guest", *flagBootTimeout)
		}
		out.Err = reason
	}
	_ = start
	return out
}

// runBootStage is the whole of stage two: resolve artifacts, pack this binary
// into an initramfs, boot N microVMs and judge what came back.
func runBootStage(ctx context.Context, r *Report) {
	if os.Geteuid() != 0 {
		r.Blocked("boot.privileges", "Root for the boot stage",
			fmt.Sprintf("running as uid %d", os.Geteuid()),
			"Giving a microVM a network interface means creating a tap device, which needs "+
				"CAP_NET_ADMIN. Re-run with sudo. This says nothing about the host.")
		return
	}

	arch := runtime.GOARCH
	fcArt, ok := firecrackerArtifacts[arch]
	if !ok {
		r.Addf("boot.arch", "Boot stage architecture", Skip, "no pinned artifacts for %s", arch)
		return
	}

	// Firecracker binary.
	fcBin := *flagFirecracker
	if fcBin == "" {
		var err error
		fcBin, err = resolveArtifact(ctx, *flagCache, "firecracker-"+firecrackerVersion, fcArt)
		if err != nil {
			r.Fail("boot.firecracker", "Firecracker binary", err.Error(),
				"Supply one with -firecracker, or allow network access to fetch the pinned release.")
			return
		}
		r.Addf("boot.firecracker", "Firecracker binary", Pass, "%s (pinned %s, checksum verified)", fcBin, firecrackerVersion)
	} else {
		r.Addf("boot.firecracker", "Firecracker binary", Info, "%s (supplied, not checksum-verified)", fcBin)
	}

	// Guest kernel.
	kernel := *flagKernel
	if kernel == "" {
		var err error
		kernel, err = resolveArtifact(ctx, *flagCache, "vmlinux-6.1.141", guestKernelArtifacts[arch])
		if err != nil {
			r.Fail("boot.kernel", "Guest kernel", err.Error(),
				"Supply one with -kernel, or allow network access to fetch the pinned CI kernel.")
			return
		}
		r.Warn("boot.kernel", "Guest kernel",
			fmt.Sprintf("using Firecracker's CI kernel (%s), not Fly's", filepath.Base(kernel)),
			"This proves the host boots a microVM. It does not prove it boots Fly's guest kernel. "+
				"Re-run with -kernel pointing at Fly's vmlinux once it is available; the config it is "+
				"built with is in reference/ for comparison in the meantime.")
	} else {
		r.Addf("boot.kernel", "Guest kernel", Pass, "%s (supplied)", kernel)
	}

	// Pack ourselves as the guest's /init.
	self, err := os.Executable()
	if err != nil {
		r.Fail("boot.initramfs", "Build initramfs", fmt.Sprintf("locate own binary: %v", err), "")
		return
	}

	// This binary becomes the guest's init, and the guest has nothing in it
	// but this binary -- no libc, no dynamic loader. So being statically
	// linked is a correctness requirement, not a build preference, and it is
	// checked here rather than discovered as a kernel panic.
	//
	// It is easy to get wrong: `go build` on a host with a C compiler defaults
	// to CGO_ENABLED=1, and this package imports net, which then links libc
	// dynamically. The resulting guest fails with "Failed to execute /init
	// (error -2)" -- ENOENT for the missing interpreter, which reads like a
	// missing file and sends you looking at the archive instead of the binary.
	if interp, dynamic, err := elfInterpreter(self); err != nil {
		r.Warn("boot.initramfs.linkage", "Statically linked",
			fmt.Sprintf("could not parse own ELF headers: %v", err),
			"Proceeding anyway. If the guest panics with \"Failed to execute /init (error -2)\", "+
				"this binary is dynamically linked and must be rebuilt with CGO_ENABLED=0.")
	} else if dynamic {
		r.Fail("boot.initramfs.linkage", "Statically linked",
			fmt.Sprintf("this binary is dynamically linked (interpreter %s)", interp),
			"The guest is this binary and nothing else -- no libc, no dynamic loader -- so a "+
				"dynamically linked build cannot be exec'd as init and the guest would panic with "+
				"\"Failed to execute /init (error -2)\". Rebuild with CGO_ENABLED=0 "+
				"(`make release`, or `CGO_ENABLED=0 go build`), or use a release binary. "+
				"Plain `go build` produces a dynamic binary on any host that has a C compiler.")
		return
	} else {
		r.Addf("boot.initramfs.linkage", "Statically linked", Pass,
			"no interpreter; the guest can exec this as init")
	}

	selfBytes, err := os.ReadFile(self)
	if err != nil {
		r.Fail("boot.initramfs", "Build initramfs", fmt.Sprintf("read own binary: %v", err), "")
		return
	}

	workDir, err := os.MkdirTemp("", "fc-preflight-")
	if err != nil {
		r.Fail("boot.workdir", "Working directory", err.Error(), "")
		return
	}
	defer os.RemoveAll(workDir)

	initramfs := filepath.Join(workDir, "initramfs.cpio")
	if err := os.WriteFile(initramfs, buildInitramfs(selfBytes), 0o600); err != nil {
		r.Fail("boot.initramfs", "Build initramfs", err.Error(), "")
		return
	}
	r.Addf("boot.initramfs", "Build initramfs", Pass,
		"packed this binary as /init (%d MiB)", len(selfBytes)>>20)

	// Boot.
	n := *flagVMs
	outcomes := make([]vmOutcome, n)
	if n == 1 {
		outcomes[0] = bootOne(ctx, 0, fcBin, kernel, initramfs, workDir)
	} else {
		done := make(chan vmOutcome, n)
		for i := 0; i < n; i++ {
			go func(i int) { done <- bootOne(ctx, i, fcBin, kernel, initramfs, workDir) }(i)
		}
		for i := 0; i < n; i++ {
			o := <-done
			outcomes[o.Index] = o
		}
	}

	judgeOutcomes(r, outcomes)
}

// judgeOutcomes turns what the guests reported into checks.
func judgeOutcomes(r *Report, outcomes []vmOutcome) {
	var failed int
	for _, o := range outcomes {
		if o.Err != "" || o.Guest == nil {
			failed++
		}
	}

	if failed > 0 {
		var detail strings.Builder
		for _, o := range outcomes {
			if o.Err == "" {
				continue
			}
			fmt.Fprintf(&detail, "vm%d: %s\n", o.Index, o.Err)
			if len(o.Console) > 0 {
				fmt.Fprintf(&detail, "  last console lines:\n")
				for _, l := range o.Console {
					fmt.Fprintf(&detail, "    %s\n", l)
				}
			}
		}
		remedy := "This is the check that matters. Everything in the preflight can pass on a host " +
			"where this fails. The console tail above is the guest's own output."
		for _, o := range outcomes {
			if d := diagnoseConsole(o.Console); d != "" {
				remedy = d
				break
			}
		}
		r.Fail("boot.launch", "Firecracker microVM boots",
			fmt.Sprintf("%d of %d microVMs failed:\n%s", failed, len(outcomes), detail.String()),
			remedy)
		return
	}

	r.Addf("boot.launch", "Firecracker microVM boots", Pass,
		"%d of %d microVMs booted, ran the workload and shut down cleanly", len(outcomes), len(outcomes))

	// Aggregate. With several microVMs the spread matters more than the mean:
	// a density run is asking what happens to the slowest one, not to the
	// average one. Every number below is therefore a mean with its range, and
	// says so -- an earlier version mixed means and vm0's own figures under
	// the same labels, which is unreadable in a report someone else has to
	// interpret.
	g := outcomes[0].Guest
	n := len(outcomes)

	stat := func(pick func(*GuestReport) float64) (mean, lo, hi float64) {
		lo, hi = math.Inf(1), math.Inf(-1)
		var sum float64
		for _, o := range outcomes {
			v := pick(o.Guest)
			sum += v
			lo = math.Min(lo, v)
			hi = math.Max(hi, v)
		}
		return sum / float64(n), lo, hi
	}
	// spread renders "X" for a single VM and "mean X (min..max over N)" for
	// several, so the one-VM case does not read as if it had a range.
	spread := func(unit string, mean, lo, hi float64) string {
		if n == 1 {
			return fmt.Sprintf("%.0f %s", mean, unit)
		}
		return fmt.Sprintf("mean %.0f %s (%.0f..%.0f over %d VMs)", mean, unit, lo, hi, n)
	}

	var netErrs []string
	for _, o := range outcomes {
		if o.Guest.NetError != "" {
			netErrs = append(netErrs, fmt.Sprintf("vm%d: %s", o.Index, o.Guest.NetError))
		}
	}

	r.Add(Result{ID: "boot.guest_kernel", Title: "Guest kernel came up", Status: Pass,
		Detail: fmt.Sprintf("%s, %d vCPU, %.0f MiB, clocksource %s",
			g.KernelVersion, g.CPUs, float64(g.MemTotalKB)/1024, g.Clocksource),
		Data: map[string]any{"cmdline": g.Cmdline, "available_clocksource": g.AvailClock}})

	// Device model. A guest that booted but found no virtio devices means
	// Firecracker and the guest kernel disagree about how devices are
	// enumerated -- the usual cause is an acpi=off boot line against a
	// Firecracker that expects ACPI.
	var haveBlk, haveNet bool
	for _, drv := range g.VirtioDevices {
		switch drv {
		case "virtio_blk":
			haveBlk = true
		case "virtio_net":
			haveNet = true
		}
	}
	switch {
	case !haveBlk || !haveNet:
		r.Fail("boot.virtio", "Guest bound virtio drivers",
			fmt.Sprintf("devices found: %v (virtio_blk=%v, virtio_net=%v)", g.VirtioDevices, haveBlk, haveNet),
			"The guest booted but did not bind a driver to every device Firecracker attached. "+
				"If the boot args include acpi=off, that is the cause: stock Firecracker enumerates "+
				"devices through ACPI on x86_64.")
	default:
		r.Addf("boot.virtio", "Guest bound virtio drivers", Pass, "%v", g.VirtioDevices)
	}

	if len(netErrs) > 0 {
		r.Fail("boot.network", "Guest networking",
			strings.Join(netErrs, "; "),
			fmt.Sprintf("The guest booted and bound virtio-net but could not reach the host over its "+
				"tap. The usual cause is a host packet filter -- see host.firewall above, and check "+
				"for a default-deny input chain or a rule dropping RFC1918 destinations, either of "+
				"which covers %s. Move the guests with -guest-net, or allow that range on the %s* "+
				"interfaces. A timeout here is about the host's policy, not about Firecracker.",
				*flagGuestNet, tapPrefix))
	} else {
		rttMean, rttLo, rttHi := stat(func(g *GuestReport) float64 { return g.NetEchoRTTus })
		tpMean, tpLo, tpHi := stat(func(g *GuestReport) float64 { return g.NetThroughput })
		r.Add(Result{ID: "boot.network", Title: "Guest networking", Status: Pass,
			Detail: fmt.Sprintf("echo RTT %s; throughput %s",
				spread("us", rttMean, rttLo, rttHi), spread("Mb/s", tpMean, tpLo, tpHi)),
			Data: map[string]any{"rtt_us_mean": rttMean, "throughput_mbps_mean": tpMean}})
	}

	bootMean, bootLo, bootHi := stat(func(g *GuestReport) float64 { return g.UptimeAtStart * 1000 })
	var wallHi float64
	for _, o := range outcomes {
		wallHi = math.Max(wallHi, o.TotalMS)
	}
	r.Add(Result{ID: "boot.timing", Title: "Boot time", Status: Info,
		Detail: fmt.Sprintf("guest reached init at %s; slowest VM took %.0f ms wall clock end to end",
			spread("ms", bootMean, bootLo, bootHi), wallHi),
		Data: map[string]any{"boot_ms_mean": bootMean, "boot_ms_min": bootLo, "boot_ms_max": bootHi,
			"wall_ms_max": wallHi}})

	// The measurements to diff against a Fly host. clock_gettime cost is the
	// single most sensitive one to nested virtualization, which is why it gets
	// its own line.
	clkMean, clkLo, clkHi := stat(func(g *GuestReport) float64 { return g.ClockReadNS })
	r.Add(Result{ID: "boot.perf.clock", Title: "Guest clock_gettime cost", Status: Info,
		Detail: fmt.Sprintf("%s per read", spread("ns", clkMean, clkLo, clkHi)),
		Data:   map[string]any{"ns_per_read_mean": clkMean, "ns_per_read_max": clkHi}})

	cpu1Mean, cpu1Lo, cpu1Hi := stat(func(g *GuestReport) float64 { return g.CPUHashMBps })
	cpuNMean, _, _ := stat(func(g *GuestReport) float64 { return g.CPUHashMBpsN })
	r.Add(Result{ID: "boot.perf.cpu", Title: "Guest CPU", Status: Info,
		Detail: fmt.Sprintf("sha256 single core %s; across %d vCPUs mean %.0f MB/s",
			spread("MB/s", cpu1Mean, cpu1Lo, cpu1Hi), g.CPUs, cpuNMean)})

	memMean, memLo, memHi := stat(func(g *GuestReport) float64 { return g.MemWriteMBps })
	r.Add(Result{ID: "boot.perf.mem", Title: "Guest memory", Status: Info,
		Detail: fmt.Sprintf("write %s", spread("MB/s", memMean, memLo, memHi))})

	if g.DiskWriteMBps > 0 {
		dwMean, dwLo, dwHi := stat(func(g *GuestReport) float64 { return g.DiskWriteMBps })
		drMean, drLo, drHi := stat(func(g *GuestReport) float64 { return g.DiskReadMBps })
		r.Add(Result{ID: "boot.perf.disk", Title: "Guest disk (virtio-blk)", Status: Info,
			Detail: fmt.Sprintf("write %s; read %s",
				spread("MB/s", dwMean, dwLo, dwHi), spread("MB/s", drMean, drLo, drHi))})
	}

	// Record every VM's full guest report in the JSON, for the diff.
	r.Add(Result{ID: "boot.raw", Title: "Raw guest reports", Status: Info,
		Detail: fmt.Sprintf("%d microVM report(s) recorded in the JSON output", len(outcomes)),
		Data:   map[string]any{"vms": outcomes}})
}
