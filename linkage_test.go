// Copyright 2026 Fly.io. Apache-2.0.

//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The boot stage packs this binary into an initramfs as the guest's /init, and
// the guest contains nothing else -- no libc, no dynamic loader. A dynamically
// linked build therefore cannot be exec'd, and the guest dies with "Failed to
// execute /init (error -2)": ENOENT for the missing interpreter, which reads
// like a missing file and sends you to inspect the archive instead of the
// binary. That cost a full debugging cycle on real hardware, so the detector
// that now catches it up front has a test.

const probeSource = `package main

import (
	"fmt"
	_ "net" // the import that pulls in cgo, and so libc, when CGO is enabled
)

func main() { fmt.Println("probe") }
`

func buildProbe(t *testing.T, cgo string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(probeSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module probe\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "probe")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building probe with CGO_ENABLED=%s: %v\n%s", cgo, err, b)
	}
	return out
}

func TestStaticBuildHasNoInterpreter(t *testing.T) {
	interp, dynamic, err := elfInterpreter(buildProbe(t, "0"))
	if err != nil {
		t.Fatalf("elfInterpreter: %v", err)
	}
	if dynamic {
		t.Errorf("CGO_ENABLED=0 build reported as dynamic, interpreter %q", interp)
	}
}

// The case that actually bit: a plain `go build` on a machine with a C
// compiler. Without a C compiler the toolchain silently produces a static
// binary and there is nothing to detect, so this asserts only where the
// precondition genuinely holds.
func TestCgoBuildIsDetectedAsDynamic(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		if _, err := exec.LookPath("cc"); err != nil {
			t.Skip("no C compiler, so CGO_ENABLED=1 cannot produce a dynamic binary here")
		}
	}
	interp, dynamic, err := elfInterpreter(buildProbe(t, "1"))
	if err != nil {
		t.Fatalf("elfInterpreter: %v", err)
	}
	if !dynamic {
		t.Fatal("CGO_ENABLED=1 build with a C compiler present reported as static; " +
			"the guard that keeps a dynamic binary out of the initramfs would not fire")
	}
	if interp == "" {
		t.Error("detected as dynamic but no interpreter path was read")
	}
}

// The console signature has to map to a sentence, because the raw output is a
// kernel stack trace and the meaningful line is one ENOENT above it.
func TestConsoleDiagnosisNamesTheLinkageFailure(t *testing.T) {
	console := []string{
		"[    0.130382] Run /init as init process",
		"[    0.130677] Failed to execute /init (error -2)",
		"[    0.131539] Kernel panic - not syncing: No working init found.",
	}
	got := diagnoseConsole(console)
	if got == "" {
		t.Fatal("no diagnosis for the exec-failure console signature")
	}
	if !contains(got, "interpreter") {
		t.Errorf("diagnosis does not mention the interpreter, which is the actual cause: %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
