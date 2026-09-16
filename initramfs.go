// Copyright 2026 Fly.io. Apache-2.0.

package main

import (
	"bytes"
	"fmt"
)

// A minimal cpio "newc" writer, enough to build an initramfs.
//
// The guest in the boot stage is not a distribution image. It is this same
// binary, packed as /init, plus the three mount points it needs. That is a
// deliberate choice: it means the boot stage needs exactly two downloaded
// artifacts (a Firecracker binary and a kernel) instead of also needing a
// root filesystem, and it means the workload running inside the microVM is
// code that ships in this repo and can be read, rather than whatever a
// downloaded rootfs happens to run at boot.

const (
	modeFile = 0o100000
	modeDir  = 0o040000
	modeChar = 0o020000
)

type cpioEntry struct {
	name string
	mode uint32 // type bits | permission bits
	data []byte
	// rdev major/minor, for device nodes only.
	rdevMajor, rdevMinor uint32
}

type cpioWriter struct {
	buf bytes.Buffer
	ino uint32
}

func (w *cpioWriter) pad() {
	for w.buf.Len()%4 != 0 {
		w.buf.WriteByte(0)
	}
}

func (w *cpioWriter) add(e cpioEntry) {
	w.ino++
	// newc: a 110-byte ASCII header of 8-hex fields after a 6-byte magic.
	// namesize counts the trailing NUL. The header plus name is padded to 4,
	// then the data is padded to 4.
	fmt.Fprintf(&w.buf, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
		w.ino,         // c_ino
		e.mode,        // c_mode
		0,             // c_uid (root)
		0,             // c_gid (root)
		1,             // c_nlink
		0,             // c_mtime (reproducible)
		len(e.data),   // c_filesize
		0,             // c_devmajor
		0,             // c_devminor
		e.rdevMajor,   // c_rdevmajor
		e.rdevMinor,   // c_rdevminor
		len(e.name)+1, // c_namesize, including NUL
		0,             // c_check, unused for newc
	)
	w.buf.WriteString(e.name)
	w.buf.WriteByte(0)
	w.pad()
	w.buf.Write(e.data)
	w.pad()
}

func (w *cpioWriter) finish() []byte {
	// The trailer is an entry named TRAILER!!! with every field zero.
	w.buf.WriteString("070701")
	for i := 0; i < 13; i++ {
		if i == 11 { // c_namesize
			fmt.Fprintf(&w.buf, "%08X", len("TRAILER!!!")+1)
			continue
		}
		if i == 4 { // c_nlink; some readers insist on 1
			fmt.Fprintf(&w.buf, "%08X", 1)
			continue
		}
		w.buf.WriteString("00000000")
	}
	w.buf.WriteString("TRAILER!!!")
	w.buf.WriteByte(0)
	w.pad()
	return w.buf.Bytes()
}

// buildInitramfs packs the given binary as /init, alongside the mount points
// the guest side needs.
//
// /dev/console is created as a real character device node (major 5, minor 1)
// rather than left to devtmpfs. The kernel opens /dev/console for PID 1 as it
// hands over, which is before init has had any chance to mount anything -- so
// without the node in the archive, the guest's first writes go nowhere and a
// boot failure looks identical to a silent hang.
func buildInitramfs(initBinary []byte) []byte {
	w := &cpioWriter{}
	for _, d := range []string{"dev", "proc", "sys", "tmp"} {
		w.add(cpioEntry{name: d, mode: modeDir | 0o755})
	}
	w.add(cpioEntry{name: "dev/console", mode: modeChar | 0o600, rdevMajor: 5, rdevMinor: 1})
	w.add(cpioEntry{name: "init", mode: modeFile | 0o755, data: initBinary})
	return w.finish()
}
