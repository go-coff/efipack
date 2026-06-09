// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package stub

import (
	"encoding/binary"
	"testing"
)

// TestAMD64BlobIsPE32Plus asserts that the embedded amd64 blob is a
// well-formed PE32+ image whose COFF Machine field matches the
// x86-64 EFI machine (0x8664). This protects against an accidental
// rebuild of the stub with the wrong GOARCH (a category of bug we hit
// once during early M0 work — see BOOTRISCV64.EFI shipping
// runtime.GOARCH=amd64 in its rodata).
func TestAMD64BlobIsPE32Plus(t *testing.T) {
	b := AMD64
	if len(b) < 0x40 {
		t.Fatalf("AMD64 blob too small (%d bytes)", len(b))
	}
	if b[0] != 'M' || b[1] != 'Z' {
		t.Fatalf("AMD64 blob is not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(b[0x3C:])
	if int(elfanew)+24 > len(b) {
		t.Fatalf("AMD64 blob truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(b[elfanew:elfanew+4]) != "PE\x00\x00" {
		t.Fatalf("AMD64 blob missing PE signature at 0x%x", elfanew)
	}
	mach := binary.LittleEndian.Uint16(b[elfanew+4:])
	if mach != 0x8664 {
		t.Fatalf("AMD64 blob Machine = 0x%04x, want 0x8664 (IMAGE_FILE_MACHINE_AMD64)", mach)
	}
	// Optional Header Magic at coffOff+20 must be 0x20b (PE32+).
	optMagic := binary.LittleEndian.Uint16(b[int(elfanew)+4+20:])
	if optMagic != 0x20b {
		t.Fatalf("AMD64 blob Optional Header Magic = 0x%x, want 0x20b (PE32+)", optMagic)
	}
}

// TestAMD64BlobNonEmpty is the cheap sanity check that the //go:embed
// directive actually pulled in the file rather than yielding a nil
// slice (which would silently degrade Pack to the sentinel envelope on
// amd64 -- exactly the bug PR2 exists to prevent).
func TestAMD64BlobNonEmpty(t *testing.T) {
	if len(AMD64) == 0 {
		t.Fatalf("AMD64 blob is empty -- //go:embed did not load blobs/amd64.efi.bin")
	}
}
