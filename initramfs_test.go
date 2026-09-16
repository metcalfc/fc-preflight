// Copyright 2026 Fly.io. Apache-2.0.

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The cpio writer is the one piece of this tool that cannot be checked by
// running the tool: if the archive is malformed the kernel does not complain,
// it boots a guest with no /init and hangs, which is indistinguishable from
// every other way a microVM fails to come up. So it is checked here, against a
// real cpio implementation rather than against our own reader.

func TestInitramfsIsReadableByCpio(t *testing.T) {
	cpio, err := exec.LookPath("cpio")
	if err != nil {
		// cpio is in coreutils-adjacent base installs everywhere this tool
		// runs. Failing rather than skipping: a skipped test is not evidence.
		t.Fatalf("cpio not found in PATH, so this test cannot prove anything: %v", err)
	}

	payload := []byte("#!/nonexistent\nthis stands in for the init binary\n")
	archive := buildInitramfs(payload)

	dir := t.TempDir()
	cmd := exec.Command(cpio, "-idmu")
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(archive)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cpio refused the archive: %v\n%s", err, stderr.String())
	}

	// /init must be there, executable, and byte-identical: the guest is the
	// same binary as the host side, so a truncated or padded copy would be a
	// binary that does not execute.
	initPath := filepath.Join(dir, "init")
	got, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatalf("no /init in the extracted archive: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("/init contents differ: got %d bytes, want %d", len(got), len(payload))
	}
	fi, err := os.Stat(initPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("/init is not executable: mode %s", fi.Mode())
	}

	for _, d := range []string{"dev", "proc", "sys", "tmp"} {
		fi, err := os.Stat(filepath.Join(dir, d))
		if err != nil {
			t.Errorf("missing mount point /%s: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("/%s is not a directory", d)
		}
	}
}

// /dev/console must be a character device node in the archive itself. The
// kernel opens it for PID 1 before init has mounted anything, so if it is
// missing the guest's output goes nowhere and a boot failure looks like a
// silent hang. Extracting device nodes needs root, so this asserts on the
// header rather than on the extracted tree.
func TestInitramfsCarriesConsoleDeviceNode(t *testing.T) {
	archive := buildInitramfs([]byte("x"))

	idx := bytes.Index(archive, []byte("dev/console"))
	if idx < 0 {
		t.Fatal("no dev/console entry in the archive")
	}
	// The 110-byte newc header precedes the name.
	hdr := archive[idx-110 : idx]
	if !bytes.HasPrefix(hdr, []byte("070701")) {
		t.Fatalf("dev/console is not preceded by a newc header: %q", hdr[:6])
	}

	field := func(n int) string { return string(hdr[6+n*8 : 6+(n+1)*8]) }

	// c_mode is field 1. S_IFCHR is 0o020000, so with 0600 permissions the
	// mode is 0o020600 == 0x2180.
	if mode := field(1); !strings.EqualFold(mode, "00002180") {
		t.Errorf("c_mode = %s, want 00002180 (S_IFCHR|0600)", mode)
	}
	// c_rdevmajor and c_rdevminor are fields 9 and 10: console is 5:1.
	if maj := field(9); !strings.EqualFold(maj, "00000005") {
		t.Errorf("c_rdevmajor = %s, want 00000005", maj)
	}
	if min := field(10); !strings.EqualFold(min, "00000001") {
		t.Errorf("c_rdevminor = %s, want 00000001", min)
	}
}

// Every entry and the trailer must land on a 4-byte boundary. A single
// misaligned entry makes the kernel stop parsing at that point, silently.
func TestInitramfsIsFourByteAligned(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 4, 5, 7, 8, 1023, 4096, 4097} {
		archive := buildInitramfs(bytes.Repeat([]byte("a"), size))
		if len(archive)%4 != 0 {
			t.Errorf("payload %d bytes: archive length %d is not 4-byte aligned", size, len(archive))
		}
		if !bytes.HasSuffix(bytes.TrimRight(archive, "\x00"), []byte("TRAILER!!!")) {
			t.Errorf("payload %d bytes: archive does not end with the cpio trailer", size)
		}
	}
}
