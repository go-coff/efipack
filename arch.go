// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package efipack

import (
	"encoding/binary"
	"fmt"
)

// Arch enumerates the four PE32+/EFI target machines efipack ships
// (or will ship, once PR2 lands the per-arch decompressor stubs).
type Arch int

const (
	// AmdArch is amd64 / x86_64. PE COFF Machine = 0x8664.
	AmdArch Arch = iota
	// ArmArch is arm64 / aarch64. PE COFF Machine = 0xaa64.
	ArmArch
	// RiscvArch is riscv64. PE COFF Machine = 0x5064.
	RiscvArch
	// LoongArch is loongarch64. PE COFF Machine = 0x6264.
	LoongArch
)

// PE/COFF Machine field values for the EFI machines we care about.
// Mirrors the constants in github.com/go-coff/peln/linker.
const (
	machineAMD64       uint16 = 0x8664
	machineARM64       uint16 = 0xaa64
	machineRISCV64     uint16 = 0x5064
	machineLoongArch64 uint16 = 0x6264
)

// String returns a short stable name for the architecture. Used in
// error messages and in the per-arch stub blob name (see
// bodyCodec.StubBlobName).
func (a Arch) String() string {
	switch a {
	case AmdArch:
		return "amd64"
	case ArmArch:
		return "arm64"
	case RiscvArch:
		return "riscv64"
	case LoongArch:
		return "loong64"
	default:
		return fmt.Sprintf("Arch(%d)", int(a))
	}
}

// machine returns the PE/COFF Machine field value for a, or 0 if a is
// not a recognised Arch.
func (a Arch) machine() uint16 {
	switch a {
	case AmdArch:
		return machineAMD64
	case ArmArch:
		return machineARM64
	case RiscvArch:
		return machineRISCV64
	case LoongArch:
		return machineLoongArch64
	default:
		return 0
	}
}

// archFromMachine maps a PE/COFF Machine value to an Arch.
func archFromMachine(m uint16) (Arch, bool) {
	switch m {
	case machineAMD64:
		return AmdArch, true
	case machineARM64:
		return ArmArch, true
	case machineRISCV64:
		return RiscvArch, true
	case machineLoongArch64:
		return LoongArch, true
	default:
		return 0, false
	}
}

// InferArch reads the PE/COFF header of pe and returns the detected
// Arch. It does the minimum amount of parsing required to read the
// Machine field — no debug/pe round-trip, so it accepts machines such
// as loong64 (0x6264) that debug/pe rejects.
func InferArch(pe []byte) (Arch, error) {
	if len(pe) < 0x40 {
		return 0, fmt.Errorf("efipack: input too short (%d bytes)", len(pe))
	}
	if pe[0] != 'M' || pe[1] != 'Z' {
		return 0, fmt.Errorf("efipack: input is not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(pe[0x3C:])
	// COFF File Header is 20 bytes starting at elfanew+4 (after "PE\0\0").
	if uint64(elfanew)+4+20 > uint64(len(pe)) {
		return 0, fmt.Errorf("efipack: truncated PE header (e_lfanew=%d)", elfanew)
	}
	if string(pe[elfanew:elfanew+4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("efipack: missing PE signature at offset %d", elfanew)
	}
	machine := binary.LittleEndian.Uint16(pe[elfanew+4:])
	a, ok := archFromMachine(machine)
	if !ok {
		return 0, fmt.Errorf("efipack: unsupported PE machine 0x%04x", machine)
	}
	return a, nil
}
