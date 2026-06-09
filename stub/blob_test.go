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

// TestARM64BlobIsPE32Plus asserts that the embedded arm64 blob is a
// well-formed PE32+ image whose COFF Machine field matches the
// aarch64 EFI machine (0xaa64). Same guard category as the amd64
// test -- protects against a wrong-GOARCH rebuild leaking through.
func TestARM64BlobIsPE32Plus(t *testing.T) {
	b := ARM64
	if len(b) < 0x40 {
		t.Fatalf("ARM64 blob too small (%d bytes)", len(b))
	}
	if b[0] != 'M' || b[1] != 'Z' {
		t.Fatalf("ARM64 blob is not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(b[0x3C:])
	if int(elfanew)+24 > len(b) {
		t.Fatalf("ARM64 blob truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(b[elfanew:elfanew+4]) != "PE\x00\x00" {
		t.Fatalf("ARM64 blob missing PE signature at 0x%x", elfanew)
	}
	mach := binary.LittleEndian.Uint16(b[elfanew+4:])
	if mach != 0xaa64 {
		t.Fatalf("ARM64 blob Machine = 0x%04x, want 0xaa64 (IMAGE_FILE_MACHINE_ARM64)", mach)
	}
	optMagic := binary.LittleEndian.Uint16(b[int(elfanew)+4+20:])
	if optMagic != 0x20b {
		t.Fatalf("ARM64 blob Optional Header Magic = 0x%x, want 0x20b (PE32+)", optMagic)
	}
}

// TestARM64BlobNonEmpty is the cheap sanity check that the //go:embed
// directive actually pulled in blobs/arm64.efi.bin.
func TestARM64BlobNonEmpty(t *testing.T) {
	if len(ARM64) == 0 {
		t.Fatalf("ARM64 blob is empty -- //go:embed did not load blobs/arm64.efi.bin")
	}
}

// TestRISCV64BlobIsPE32Plus asserts that the embedded riscv64 blob is
// a well-formed PE32+ image whose COFF Machine field matches the
// riscv64 EFI machine (0x5064). Same guard category as the amd64/arm64
// tests -- protects against a wrong-GOARCH rebuild leaking through.
func TestRISCV64BlobIsPE32Plus(t *testing.T) {
	b := RISCV64Blob
	if len(b) < 0x40 {
		t.Fatalf("RISCV64 blob too small (%d bytes)", len(b))
	}
	if b[0] != 'M' || b[1] != 'Z' {
		t.Fatalf("RISCV64 blob is not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(b[0x3C:])
	if int(elfanew)+24 > len(b) {
		t.Fatalf("RISCV64 blob truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(b[elfanew:elfanew+4]) != "PE\x00\x00" {
		t.Fatalf("RISCV64 blob missing PE signature at 0x%x", elfanew)
	}
	mach := binary.LittleEndian.Uint16(b[elfanew+4:])
	if mach != 0x5064 {
		t.Fatalf("RISCV64 blob Machine = 0x%04x, want 0x5064 (IMAGE_FILE_MACHINE_RISCV64)", mach)
	}
	optMagic := binary.LittleEndian.Uint16(b[int(elfanew)+4+20:])
	if optMagic != 0x20b {
		t.Fatalf("RISCV64 blob Optional Header Magic = 0x%x, want 0x20b (PE32+)", optMagic)
	}
}

// TestRISCV64BlobNonEmpty is the cheap sanity check that the //go:embed
// directive actually pulled in blobs/riscv64.efi.bin.
func TestRISCV64BlobNonEmpty(t *testing.T) {
	if len(RISCV64Blob) == 0 {
		t.Fatalf("RISCV64 blob is empty -- //go:embed did not load blobs/riscv64.efi.bin")
	}
}

// TestLoongArch64BlobIsPE32Plus asserts that the embedded loong64 blob
// is a well-formed PE32+ image whose COFF Machine field matches the
// LoongArch64 EFI machine (0x6264). Same guard category as the
// amd64/arm64 tests -- protects against a wrong-GOARCH rebuild leaking
// through.
func TestLoongArch64BlobIsPE32Plus(t *testing.T) {
	b := LoongArch64Blob
	if len(b) < 0x40 {
		t.Fatalf("LoongArch64 blob too small (%d bytes)", len(b))
	}
	if b[0] != 'M' || b[1] != 'Z' {
		t.Fatalf("LoongArch64 blob is not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(b[0x3C:])
	if int(elfanew)+24 > len(b) {
		t.Fatalf("LoongArch64 blob truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(b[elfanew:elfanew+4]) != "PE\x00\x00" {
		t.Fatalf("LoongArch64 blob missing PE signature at 0x%x", elfanew)
	}
	mach := binary.LittleEndian.Uint16(b[elfanew+4:])
	if mach != 0x6264 {
		t.Fatalf("LoongArch64 blob Machine = 0x%04x, want 0x6264 (IMAGE_FILE_MACHINE_LOONGARCH64)", mach)
	}
	optMagic := binary.LittleEndian.Uint16(b[int(elfanew)+4+20:])
	if optMagic != 0x20b {
		t.Fatalf("LoongArch64 blob Optional Header Magic = 0x%x, want 0x20b (PE32+)", optMagic)
	}
}

// TestLoongArch64BlobNonEmpty is the cheap sanity check that the
// //go:embed directive actually pulled in blobs/loong64.efi.bin.
func TestLoongArch64BlobNonEmpty(t *testing.T) {
	if len(LoongArch64Blob) == 0 {
		t.Fatalf("LoongArch64 blob is empty -- //go:embed did not load blobs/loong64.efi.bin")
	}
}
