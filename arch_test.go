// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package efipack

import (
	"encoding/binary"
	"strings"
	"testing"
)

// makeMinimalPE returns the smallest byte sequence that satisfies
// InferArch's parser: a DOS stub with e_lfanew, the PE signature,
// and a 20-byte COFF header whose Machine field is set to mach.
// Used only by tests; covers all four supported machines plus the
// rejection path.
func makeMinimalPE(mach uint16) []byte {
	pe := make([]byte, 0x40+4+20)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40)
	copy(pe[0x40:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x44:], mach)
	return pe
}

func TestInferArchAllSupportedMachines(t *testing.T) {
	cases := []struct {
		name string
		mach uint16
		want Arch
	}{
		{"amd64", machineAMD64, AmdArch},
		{"arm64", machineARM64, ArmArch},
		{"riscv64", machineRISCV64, RiscvArch},
		{"loong64", machineLoongArch64, LoongArch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := InferArch(makeMinimalPE(c.mach))
			if err != nil {
				t.Fatalf("InferArch: %v", err)
			}
			if got != c.want {
				t.Fatalf("InferArch = %v, want %v", got, c.want)
			}
			// Round-trip: each supported Arch's machine() must match
			// the value we used to construct the PE.
			if got.machine() != c.mach {
				t.Fatalf("Arch(%v).machine() = 0x%x, want 0x%x", got, got.machine(), c.mach)
			}
		})
	}
}

func TestInferArchRejection(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantSub string
	}{
		{"too-short", []byte{0x4d, 0x5a}, "too short"},
		{"not-mz", append([]byte{'X', 'Y'}, make([]byte, 0x60)...), "not a PE/MZ"},
		{
			name: "truncated-header",
			in: func() []byte {
				b := make([]byte, 0x40)
				b[0], b[1] = 'M', 'Z'
				// e_lfanew points past end of buffer
				binary.LittleEndian.PutUint32(b[0x3C:], 0x1000)
				return b
			}(),
			wantSub: "truncated",
		},
		{
			name: "missing-pe-sig",
			in: func() []byte {
				b := make([]byte, 0x40+4+20)
				b[0], b[1] = 'M', 'Z'
				binary.LittleEndian.PutUint32(b[0x3C:], 0x40)
				copy(b[0x40:], []byte("XX\x00\x00"))
				return b
			}(),
			wantSub: "missing PE signature",
		},
		{
			name:    "unsupported-machine",
			in:      makeMinimalPE(0xdead),
			wantSub: "unsupported PE machine",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := InferArch(c.in)
			if err == nil {
				t.Fatalf("InferArch: want error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("InferArch error = %q, want substring %q", err.Error(), c.wantSub)
			}
		})
	}
}

func TestArchString(t *testing.T) {
	cases := []struct {
		a    Arch
		want string
	}{
		{AmdArch, "amd64"},
		{ArmArch, "arm64"},
		{RiscvArch, "riscv64"},
		{LoongArch, "loong64"},
		{Arch(42), "Arch(42)"},
	}
	for _, c := range cases {
		if got := c.a.String(); got != c.want {
			t.Errorf("Arch(%d).String() = %q, want %q", int(c.a), got, c.want)
		}
	}
}

func TestArchMachineUnknown(t *testing.T) {
	if m := Arch(99).machine(); m != 0 {
		t.Fatalf("Arch(99).machine() = 0x%x, want 0", m)
	}
}

func TestArchFromMachineUnknown(t *testing.T) {
	if _, ok := archFromMachine(0x1234); ok {
		t.Fatalf("archFromMachine(0x1234) = ok, want !ok")
	}
}
