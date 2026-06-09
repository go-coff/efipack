// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package efipack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// fixturePE builds a synthetic PE32+/EFI image for arch a. The result
// is structurally valid (the InferArch parser accepts it) and has a
// payload region the compression test can prove travels through Pack
// untouched. The bytes after the COFF header are random-ish but
// deterministic, exercising the compressor on a non-trivial buffer.
func fixturePE(a Arch, payloadLen int) []byte {
	mach := a.machine()
	const total = 0x40 + 4 + 20
	pe := make([]byte, total+payloadLen)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40)
	copy(pe[0x40:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x44:], mach)
	// Fill the synthetic body with a repeating pattern so flate has
	// something to compress (a uniform-random buffer barely compresses
	// at all and would mask the codec entirely).
	for i := 0; i < payloadLen; i++ {
		pe[total+i] = byte((i * 37) & 0xff)
	}
	return pe
}

// roundTripCheck packs in, then reverses Pack's envelope by walking
// the .payload section and inflating the body. The result must equal
// the original input byte-for-byte. This is PR1's load-bearing
// acceptance test: it proves the format is recoverable even before
// PR2's runtime stub exists.
func roundTripCheck(t *testing.T, in []byte, opts Options) PackResult {
	t.Helper()
	var packed bytes.Buffer
	res, err := Pack(bytes.NewReader(in), &packed, opts)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if res.OriginalSize != int64(len(in)) {
		t.Fatalf("OriginalSize = %d, want %d", res.OriginalSize, len(in))
	}
	if res.PackedSize != int64(packed.Len()) {
		t.Fatalf("PackedSize = %d, want %d", res.PackedSize, packed.Len())
	}

	// Pull the .payload section out and check the header.
	algo, uncompressed, body, err := ReadPayload(packed.Bytes())
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if uncompressed != uint64(len(in)) {
		t.Fatalf("payload header uncompressed = %d, want %d", uncompressed, len(in))
	}
	wantAlgo := payloadAlgoTag(opts.Compressor)
	if algo != wantAlgo {
		t.Fatalf("payload algo = %q, want %q", algo, wantAlgo)
	}
	if int64(len(body)) != res.CompressedSize {
		t.Fatalf("payload body = %d bytes, header says %d", len(body), res.CompressedSize)
	}

	// Decompress and compare to the original input.
	codec, err := switchCompressor(opts.Compressor, opts.Level)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	var dec bytes.Buffer
	if err := codec.Decode(&dec, body); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), in) {
		t.Fatalf("round-trip mismatch: decoded %d bytes, want %d", dec.Len(), len(in))
	}

	// For arches still on the PR1 sentinel envelope, the .stub
	// placeholder must still carry the marker so downstream tooling
	// (and the PR2-next-sprint patcher) can locate the slot reliably.
	// For arches with a real per-arch stub blob shipped in this
	// build (PR2: amd64), the envelope IS the stub PE and there is
	// no .stub section to assert on -- the stub's own .text holds
	// the runtime decompressor, and Pack just appends .payload.
	arch := res.Arch
	if archStubBlob(arch) == nil {
		stub, err := findSection(packed.Bytes(), stubSectionName)
		if err != nil {
			t.Fatalf("findSection(.stub): %v", err)
		}
		if !bytes.HasPrefix(stub, []byte(stubPlaceholderSentinel)) {
			t.Fatalf(".stub does not start with %q", stubPlaceholderSentinel)
		}
	}
	return res
}

func TestPackRoundTripAllArches(t *testing.T) {
	// 8 KiB of patterned bytes is enough to make flate produce a
	// measurably smaller body while staying small enough to run quickly
	// under -race.
	const payloadLen = 8 * 1024
	cases := []struct {
		name string
		arch Arch
	}{
		{"amd64", AmdArch},
		{"arm64", ArmArch},
		{"riscv64", RiscvArch},
		{"loong64", LoongArch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := fixturePE(c.arch, payloadLen)
			res := roundTripCheck(t, in, Options{Compressor: Flate})
			if res.Arch != c.arch {
				t.Fatalf("result.Arch = %v, want %v", res.Arch, c.arch)
			}
			if res.Compressor != Flate {
				t.Fatalf("result.Compressor = %v, want Flate", res.Compressor)
			}
		})
	}
}

func TestPackDefaultOptionsAreFlate(t *testing.T) {
	in := fixturePE(AmdArch, 2048)
	res := roundTripCheck(t, in, Options{})
	if res.Compressor != Flate {
		t.Fatalf("default Compressor = %v, want Flate", res.Compressor)
	}
}

func TestPackBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"unsupported-machine", makeMinimalPE(0xdead)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := Pack(bytes.NewReader(c.in), &out, Options{}); err == nil {
				t.Fatalf("Pack: want error, got nil")
			}
		})
	}
}

func TestPackReadError(t *testing.T) {
	var out bytes.Buffer
	_, err := Pack(errReader{}, &out, Options{})
	if err == nil {
		t.Fatalf("Pack: want read error, got nil")
	}
	if !strings.Contains(err.Error(), "read input") {
		t.Fatalf("Pack error = %q, want substring %q", err.Error(), "read input")
	}
}

func TestPackCompressorError(t *testing.T) {
	in := fixturePE(AmdArch, 64)
	var out bytes.Buffer
	_, err := Pack(bytes.NewReader(in), &out, Options{Compressor: LZFSE})
	if !errors.Is(err, ErrCompressorNotImplemented) {
		t.Fatalf("Pack(LZFSE) = %v, want ErrCompressorNotImplemented", err)
	}
}

func TestPackEncodeError(t *testing.T) {
	in := fixturePE(AmdArch, 64)
	var out bytes.Buffer
	// flate.NewWriter rejects level 42 → propagates as an Encode error.
	_, err := Pack(bytes.NewReader(in), &out, Options{Compressor: Flate, Level: 42})
	if err == nil {
		t.Fatalf("Pack: want encode error, got nil")
	}
}

func TestPackWriteError(t *testing.T) {
	in := fixturePE(AmdArch, 64)
	if _, err := Pack(bytes.NewReader(in), errWriter{}, Options{}); err == nil {
		t.Fatalf("Pack: want write error, got nil")
	}
}

func TestBuildSkeletonUnsupportedArch(t *testing.T) {
	if _, err := buildSkeleton(Arch(99)); err == nil {
		t.Fatalf("buildSkeleton(99): want error, got nil")
	}
}

func TestPayloadAlgoTagUnknown(t *testing.T) {
	if got := payloadAlgoTag(Compressor(99)); got != "????" {
		t.Fatalf("payloadAlgoTag(99) = %q, want %q", got, "????")
	}
}

func TestPayloadAlgoTagKnown(t *testing.T) {
	cases := map[Compressor]string{
		Flate: "FLAT",
		LZFSE: "LZFS",
		LZ4:   "LZ4 ",
	}
	for c, want := range cases {
		if got := payloadAlgoTag(c); got != want {
			t.Errorf("payloadAlgoTag(%v) = %q, want %q", c, got, want)
		}
	}
}

func TestReadPayloadErrors(t *testing.T) {
	// Build a known-good packed image so we can mutate copies of it.
	in := fixturePE(AmdArch, 1024)
	var packed bytes.Buffer
	if _, err := Pack(bytes.NewReader(in), &packed, Options{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	good := packed.Bytes()

	// Locate the .payload file offset so we can corrupt its header.
	payloadOff := mustFindSectionOff(t, good, payloadSectionName)

	t.Run("short-payload", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		// Truncate the .payload section by overwriting the section
		// header's VirtualSize / RawSize fields.
		hdrOff := mustFindSectionHeaderOff(t, bad, payloadSectionName)
		binary.LittleEndian.PutUint32(bad[hdrOff+8:], 4)  // VirtualSize
		binary.LittleEndian.PutUint32(bad[hdrOff+16:], 4) // RawSize (file-aligned but we just need the read path to think 4 bytes)
		if _, _, _, err := ReadPayload(bad); err == nil {
			t.Fatalf("ReadPayload: want short error, got nil")
		}
	})

	t.Run("bad-magic", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		copy(bad[payloadOff:], []byte("XXXX"))
		if _, _, _, err := ReadPayload(bad); err == nil {
			t.Fatalf("ReadPayload: want magic error, got nil")
		}
	})

	t.Run("truncated-compressed", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		// Inflate the declared compressed-size beyond what the section
		// actually holds.
		binary.LittleEndian.PutUint64(bad[payloadOff+16:], 1<<40)
		if _, _, _, err := ReadPayload(bad); err == nil {
			t.Fatalf("ReadPayload: want truncated error, got nil")
		}
	})

	t.Run("section-missing", func(t *testing.T) {
		// A skeleton (no .payload) is a valid PE we can hand to
		// ReadPayload; expect "not found".
		skel, err := buildSkeleton(AmdArch)
		if err != nil {
			t.Fatalf("buildSkeleton: %v", err)
		}
		if _, _, _, err := ReadPayload(skel); err == nil {
			t.Fatalf("ReadPayload(skeleton): want missing-section error, got nil")
		}
	})
}

func TestFindSectionErrors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"not-mz", append([]byte{'X', 'Y'}, make([]byte, 0x60)...)},
		{"truncated-header", func() []byte {
			b := make([]byte, 0x40)
			b[0], b[1] = 'M', 'Z'
			binary.LittleEndian.PutUint32(b[0x3C:], 0x1000)
			return b
		}()},
		{"missing-pe-sig", func() []byte {
			b := make([]byte, 0x40+4+20)
			b[0], b[1] = 'M', 'Z'
			binary.LittleEndian.PutUint32(b[0x3C:], 0x40)
			copy(b[0x40:], []byte("XX\x00\x00"))
			return b
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := findSection(c.in, ".whatever"); err == nil {
				t.Fatalf("findSection: want error, got nil")
			}
		})
	}
}

func TestFindSectionTruncatedSectionTable(t *testing.T) {
	// Build a PE that claims to have many sections but is too short.
	pe := make([]byte, 0x40+4+20+240) // headers + optional header but no section entries
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40)
	copy(pe[0x40:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x44:], machineAMD64)
	binary.LittleEndian.PutUint16(pe[0x46:], 99) // NumberOfSections=99
	binary.LittleEndian.PutUint16(pe[0x40+4+16:], 240)
	if _, err := findSection(pe, ".x"); err == nil {
		t.Fatalf("findSection: want truncated-table error, got nil")
	}
}

func TestFindSectionPointsPastEnd(t *testing.T) {
	// Build a one-section PE whose section.FileOffset points past EOF.
	const optLen = 240
	hdrTotal := 0x40 + 4 + 20 + optLen + 40
	pe := make([]byte, hdrTotal)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40)
	copy(pe[0x40:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x44:], machineAMD64)
	binary.LittleEndian.PutUint16(pe[0x46:], 1)
	binary.LittleEndian.PutUint16(pe[0x40+4+16:], optLen)
	secOff := 0x40 + 4 + 20 + optLen
	copy(pe[secOff:secOff+8], ".bogus")
	binary.LittleEndian.PutUint32(pe[secOff+8:], 16)        // VirtualSize
	binary.LittleEndian.PutUint32(pe[secOff+16:], 16)       // RawSize
	binary.LittleEndian.PutUint32(pe[secOff+20:], 0xfffff0) // FileOffset past end
	if _, err := findSection(pe, ".bogus"); err == nil {
		t.Fatalf("findSection: want past-end error, got nil")
	}
}

func TestPackPlaceholderEntryPointsIntoStub(t *testing.T) {
	// PR1 acceptance only applies to arches still on the placeholder
	// skeleton. For arches with a real stub blob, the entry point
	// lives in the stub PE's .text (whatever the TamaGo linker chose)
	// -- not in a .stub section by name. We pick an arch that's still
	// on the sentinel so this invariant remains testable until all
	// four arches have stubs.
	var sentinelArch Arch = -1
	for _, a := range []Arch{ArmArch, RiscvArch, LoongArch, AmdArch} {
		if archStubBlob(a) == nil {
			sentinelArch = a
			break
		}
	}
	if sentinelArch == -1 {
		t.Skip("all arches now have real stub blobs; placeholder entry test is moot")
	}
	in := fixturePE(sentinelArch, 256)
	var packed bytes.Buffer
	if _, err := Pack(bytes.NewReader(in), &packed, Options{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	pe := packed.Bytes()
	elfanew := binary.LittleEndian.Uint32(pe[0x3C:])
	optOff := int(elfanew) + 4 + 20
	entryRVA := binary.LittleEndian.Uint32(pe[optOff+16:])

	stubHdr := mustFindSectionHeaderOff(t, pe, stubSectionName)
	stubRVA := binary.LittleEndian.Uint32(pe[stubHdr+12:])
	stubVS := binary.LittleEndian.Uint32(pe[stubHdr+8:])
	if entryRVA < stubRVA || entryRVA >= stubRVA+stubVS+1 {
		t.Fatalf("entry RVA 0x%x not inside .stub [0x%x, 0x%x)", entryRVA, stubRVA, stubRVA+stubVS)
	}
}

// TestPackAmd64UsesRealStub asserts that packing on amd64 produces an
// envelope that IS the embedded stub PE (sections preserved + .payload
// appended), not the placeholder skeleton. This is the PR2 amd64
// acceptance: the output PE has the stub's .text/.rodata/.data/.reloc
// sections AND a freshly appended .payload, and does NOT have a .stub
// section.
func TestPackAmd64UsesRealStub(t *testing.T) {
	if archStubBlob(AmdArch) == nil {
		t.Skip("amd64 stub blob not present in this build")
	}
	in := fixturePE(AmdArch, 512)
	var packed bytes.Buffer
	if _, err := Pack(bytes.NewReader(in), &packed, Options{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	pe := packed.Bytes()
	if _, err := findSection(pe, payloadSectionName); err != nil {
		t.Fatalf("packed image missing .payload: %v", err)
	}
	if _, err := findSection(pe, stubSectionName); err == nil {
		t.Fatalf("packed amd64 image unexpectedly has a .stub section -- stub envelope should use its own .text/.rodata/.data/.reloc")
	}
	// Must contain the stub's .text by name (TamaGo PIE convention).
	if _, err := findSection(pe, ".text"); err != nil {
		t.Fatalf("packed amd64 image missing stub .text section: %v", err)
	}
}

func TestAlignUp32Edges(t *testing.T) {
	cases := []struct {
		v, align, want uint32
	}{
		{0, 0, 0},     // align == 0 short-circuit
		{17, 0, 17},   // align == 0 short-circuit (non-zero v)
		{16, 16, 16},  // rem == 0 short-circuit
		{17, 16, 32},  // rem != 0 → round up
		{0, 0x200, 0}, // 0 with non-zero align
	}
	for _, c := range cases {
		if got := alignUp32(c.v, c.align); got != c.want {
			t.Errorf("alignUp32(%d, %d) = %d, want %d", c.v, c.align, got, c.want)
		}
	}
}

func TestFindSectionRawSmallerThanVirtual(t *testing.T) {
	// Build a PE whose section reports VirtualSize > RawSize. Our
	// findSection clamps the returned slice to RawSize so we don't
	// over-read the file. The packed images we emit never hit this
	// (RawSize >= VirtualSize by construction), but PE allows it for
	// BSS-style sections, so we test the safety net.
	const optLen = 240
	const stubBody = "hello"
	hdrTotal := 0x40 + 4 + 20 + optLen + 40
	totalSize := alignUp32(uint32(hdrTotal), 0x200) + uint32(len(stubBody))
	pe := make([]byte, totalSize)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3C:], 0x40)
	copy(pe[0x40:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x44:], machineAMD64)
	binary.LittleEndian.PutUint16(pe[0x46:], 1)
	binary.LittleEndian.PutUint16(pe[0x40+4+16:], optLen)
	secOff := 0x40 + 4 + 20 + optLen
	bodyOff := alignUp32(uint32(hdrTotal), 0x200)
	copy(pe[secOff:secOff+8], ".bss")
	// Declare a VirtualSize larger than RawSize — common for .bss.
	binary.LittleEndian.PutUint32(pe[secOff+8:], 99)                     // VirtualSize
	binary.LittleEndian.PutUint32(pe[secOff+16:], uint32(len(stubBody))) // RawSize
	binary.LittleEndian.PutUint32(pe[secOff+20:], bodyOff)               // FileOffset
	copy(pe[bodyOff:], stubBody)

	got, err := findSection(pe, ".bss")
	if err != nil {
		t.Fatalf("findSection: %v", err)
	}
	if string(got) != stubBody {
		t.Fatalf("findSection = %q, want %q (clamped to RawSize)", got, stubBody)
	}
}

// errReader returns an error on the first Read.
type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// errWriter returns an error on every Write.
type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

// mustFindSectionOff returns the file offset of the named section's
// raw data. Fails the test if absent.
func mustFindSectionOff(t *testing.T, pe []byte, name string) int {
	t.Helper()
	hdrOff := mustFindSectionHeaderOff(t, pe, name)
	return int(binary.LittleEndian.Uint32(pe[hdrOff+20:]))
}

// mustFindSectionHeaderOff returns the file offset of the named
// section's 40-byte IMAGE_SECTION_HEADER entry inside the section
// table. Fails the test if absent.
func mustFindSectionHeaderOff(t *testing.T, pe []byte, name string) int {
	t.Helper()
	elfanew := binary.LittleEndian.Uint32(pe[0x3C:])
	coffOff := int(elfanew) + 4
	numSections := binary.LittleEndian.Uint16(pe[coffOff+2:])
	sizeOfOpt := binary.LittleEndian.Uint16(pe[coffOff+16:])
	secTableStart := coffOff + 20 + int(sizeOfOpt)
	for i := 0; i < int(numSections); i++ {
		off := secTableStart + i*40
		if trimNUL(pe[off:off+8]) == name {
			return off
		}
	}
	t.Fatalf("section %q not found", name)
	return -1
}
