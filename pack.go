// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

// Package efipack compresses PE32+/EFI binaries into a self-extracting
// PE32+/EFI image. PR1 (this revision) ships the host-side compression
// API, the PE32+ envelope assembly, and tests; the per-arch runtime
// decompressor stub lands in PR2 and the pectl CLI integration in PR3.
package efipack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-coff/peln/appender"

	"github.com/go-coff/efipack/stub"
)

// Wire-format constants for the .payload header. The runtime stub
// (PR2) re-reads these to locate, size, and verify the body. Keeping
// them stable across all algorithms means we can swap compressors
// without breaking pre-existing packed binaries.
const (
	payloadMagic       = "CBP0"        // cloud-boot pack v0
	payloadHeaderSize  = 4 + 4 + 8 + 8 // magic + algo + uncompressed_size + compressed_size
	payloadSectionName = ".payload"
	stubSectionName    = ".stub"
	// PR1 sentinel: PR2 will overwrite the .stub section body with the
	// real per-arch decompressor blob. If a runtime tries to execute
	// this placeholder, it will fault — that is by design until PR2.
	stubPlaceholderSentinel = "TODO_STUB"
)

// payloadAlgoTag maps a Compressor to the 4-byte tag stamped in the
// .payload header.
func payloadAlgoTag(c Compressor) string {
	switch c {
	case Flate:
		return "FLAT"
	case LZFSE:
		return "LZFS"
	case LZ4:
		return "LZ4 "
	default:
		return "????"
	}
}

// Options controls Pack. The zero value is sensible (Flate at the
// stdlib default level).
type Options struct {
	Compressor Compressor // defaults to Flate
	Level      int        // compression level passed to the underlying codec; 0 = codec default
}

// PackResult summarises a successful Pack call. Sizes are in bytes.
//
// PR1 leaves StubSize at 0 because the .stub section is the
// placeholder; PR2 will add a StubSize field carrying the real
// per-arch blob length.
type PackResult struct {
	OriginalSize   int64
	CompressedSize int64 // size of the compressed body inside .payload (excludes the 24-byte header)
	PackedSize     int64 // size of the output PE32+ on disk
	Compressor     Compressor
	Arch           Arch
}

// Pack reads a PE32+/EFI image from in, compresses it, and writes a
// self-extracting PE32+/EFI envelope to out.
//
// PR1 acceptance: the output is structurally a valid PE32+ image
// (correct DOS stub, PE signature, COFF header with the input arch's
// Machine field, optional header, section table with `.stub` and
// `.payload`), but the `.stub` section is a placeholder containing
// only the sentinel "TODO_STUB". Firmware will load the image, jump
// to the entry point, and fault — by design. PR2 replaces the .stub
// body with the real per-arch decompressor blob, after which the
// output becomes a runnable self-extracting EFI.
//
// Round-trip is guaranteed today: the bytes inside .payload, when
// fed back through the matching bodyCodec.Decode, reproduce the
// input byte-for-byte. This is what the host tests exercise.
func Pack(in io.Reader, out io.Writer, opts Options) (PackResult, error) {
	src, err := io.ReadAll(in)
	if err != nil {
		return PackResult{}, fmt.Errorf("efipack: read input: %w", err)
	}
	return packBytes(src, out, opts)
}

// packBytes is the in-memory core; Pack is the io.Reader/Writer
// wrapper.
func packBytes(src []byte, out io.Writer, opts Options) (PackResult, error) {
	arch, err := InferArch(src)
	if err != nil {
		return PackResult{}, err
	}
	codec, err := switchCompressor(opts.Compressor, opts.Level)
	if err != nil {
		return PackResult{}, err
	}

	// Compress the entire input as opaque bytes. The runtime stub will
	// decompress straight back into an EFI image and chain-load it via
	// gBS->LoadImage + gBS->StartImage.
	var body bytes.Buffer
	if err := codec.Encode(&body, src); err != nil {
		return PackResult{}, err
	}
	compressed := body.Bytes()

	// Wrap with the .payload header so the runtime stub can locate the
	// body, know which algorithm produced it, and allocate the exact
	// number of pages needed for decompression.
	payload := make([]byte, 0, payloadHeaderSize+len(compressed))
	payload = append(payload, []byte(payloadMagic)...)
	payload = append(payload, []byte(payloadAlgoTag(opts.Compressor))...)
	var sz [8]byte
	binary.LittleEndian.PutUint64(sz[:], uint64(len(src)))
	payload = append(payload, sz[:]...)
	binary.LittleEndian.PutUint64(sz[:], uint64(len(compressed)))
	payload = append(payload, sz[:]...)
	payload = append(payload, compressed...)

	// Build the envelope base PE. For architectures that have a real
	// per-arch decompressor stub blob (PR2: amd64 only), use the
	// stub's complete PE32+ as the envelope and append .payload to
	// it directly; the stub's entry point will, at firmware load
	// time, walk the section table to find .payload, decompress it
	// and chain-boot. For architectures still on the PR1 sentinel
	// path, fall back to the placeholder skeleton (the resulting
	// PE is structurally valid but will fault if the firmware ever
	// jumps to its .stub body — by design until PR2-next-sprint).
	envelope, err := envelopeBase(arch)
	if err != nil {
		return PackResult{}, err
	}
	packed, err := appender.Append(envelope, []appender.Section{
		{
			Name:            payloadSectionName,
			Data:            payload,
			Characteristics: appender.DefaultCharacteristics,
		},
	})
	if err != nil {
		return PackResult{}, fmt.Errorf("efipack: append payload: %w", err)
	}

	if _, err := out.Write(packed); err != nil {
		return PackResult{}, fmt.Errorf("efipack: write output: %w", err)
	}

	return PackResult{
		OriginalSize:   int64(len(src)),
		CompressedSize: int64(len(compressed)),
		PackedSize:     int64(len(packed)),
		Compressor:     opts.Compressor,
		Arch:           arch,
	}, nil
}

// envelopeBase returns the base PE32+ image that .payload will be
// appended to.
//
// For architectures whose runtime decompressor stub is shipped in
// this build (currently amd64), it returns the full stub PE — the
// stub's headers, .text/.rodata/.data/.reloc sections are preserved
// byte-for-byte, and appender.Append slots .payload in after the
// last existing section without disturbing any existing RVA. The
// resulting PE is a runnable self-extracting EFI.
//
// For architectures still on the PR1 placeholder path
// (arm64/riscv64/loong64), it returns buildSkeleton's TODO_STUB
// skeleton. The output PE is structurally valid (firmware loads it
// without complaint) but faults on entry — by design until the
// per-arch stub lands.
func envelopeBase(a Arch) ([]byte, error) {
	if blob := archStubBlob(a); blob != nil {
		// Defensive copy so an appender bug or future caller mutating
		// the returned slice can't corrupt the embedded blob.
		out := make([]byte, len(blob))
		copy(out, blob)
		return out, nil
	}
	return buildSkeleton(a)
}

// archStubBlob returns the embedded per-arch decompressor stub PE,
// or nil if no stub ships for a in this build.
func archStubBlob(a Arch) []byte {
	switch a {
	case AmdArch:
		return stub.AMD64
	default:
		return nil
	}
}

// PE32+ envelope layout constants. Matches what peln/linker emits so
// that downstream tooling (pectl, signing, debug tools) sees the same
// shape for both linked-from-objects and packed images.
const (
	dosHeaderSize  = 0x40
	peSignature    = "PE\x00\x00"
	peSigSize      = 4
	coffHeaderLen  = 20
	optHeaderLen   = 240 // PE32+ (16 data directories x 8 bytes + 112 base)
	sectionEntrySz = 40
	numDataDirs    = 16

	fileAlignment    uint32 = 0x200  // 512
	sectionAlignment uint32 = 0x1000 // 4096
	defaultImageBase uint64 = 0x10000
	efiSubsystem     uint16 = 10 // IMAGE_SUBSYSTEM_EFI_APPLICATION

	// PE/COFF section characteristics. Mirrors peln/appender's
	// SCN_* constants — duplicated here to keep PE assembly self-
	// contained.
	scnCntInitData uint32 = 0x00000040
	scnCntCode     uint32 = 0x00000020
	scnMemExecute  uint32 = 0x20000000
	scnMemRead     uint32 = 0x40000000
)

// HeaderReserve is the slack we leave between the section table and
// the first section's raw data, so that appender.Append can grow the
// section table without re-laying-out the file. We reserve one full
// FileAlignment block, which is plenty for any reasonable number of
// extra sections (8 entries per 320 bytes => fits dozens of sections).
const skeletonHeaderReserve uint32 = 0x400

// buildSkeleton produces a minimal but valid PE32+/EFI image
// containing only the .stub section (the placeholder body) for the
// given architecture. PR2 will replace the .stub body in-place with
// the real per-arch decompressor blob.
func buildSkeleton(a Arch) ([]byte, error) {
	mach := a.machine()
	if mach == 0 {
		return nil, fmt.Errorf("efipack: unsupported arch %s", a)
	}

	// Section body: just the sentinel. PR2's stub will be much larger
	// (a few hundred KiB at most). The stub section is marked as RX
	// because the firmware will eventually jump into it via the entry
	// point — even though the placeholder is non-executable bytes.
	stubBody := []byte(stubPlaceholderSentinel)

	// File layout:
	//   [0, sizeOfHeaders)          : DOS + PE sig + COFF + opt + section table + padding
	//   [sizeOfHeaders, ...)        : .stub raw bytes (file-aligned)
	headerTotal := dosHeaderSize + peSigSize + coffHeaderLen + optHeaderLen + sectionEntrySz*1
	sizeOfHeaders := alignUp32(uint32(headerTotal), fileAlignment)
	if skeletonHeaderReserve > sizeOfHeaders {
		sizeOfHeaders = skeletonHeaderReserve
	}

	stubRVA := alignUp32(sizeOfHeaders, sectionAlignment)
	stubFileOff := sizeOfHeaders
	stubVirtualSize := uint32(len(stubBody))
	stubRawSize := alignUp32(stubVirtualSize, fileAlignment)
	sizeOfImage := alignUp32(stubRVA+stubVirtualSize, sectionAlignment)
	fileSize := stubFileOff + stubRawSize

	// Entry point points to the start of the .stub section. This is
	// where PR2's real per-arch decompressor begins.
	entryRVA := stubRVA

	buf := make([]byte, fileSize)

	// ----- DOS header -----
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], dosHeaderSize)

	// ----- PE signature -----
	off := dosHeaderSize
	copy(buf[off:], []byte(peSignature))
	off += peSigSize

	// ----- COFF File Header -----
	binary.LittleEndian.PutUint16(buf[off+0:], mach)
	binary.LittleEndian.PutUint16(buf[off+2:], 1) // NumberOfSections (.stub only; .payload added by appender)
	// TimeDateStamp +4..+7 = 0 (deterministic)
	// PointerToSymbolTable +8..+11 = 0
	// NumberOfSymbols +12..+15 = 0
	binary.LittleEndian.PutUint16(buf[off+16:], optHeaderLen)
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	binary.LittleEndian.PutUint16(buf[off+18:], 0x0022)
	off += coffHeaderLen

	// ----- Optional Header (PE32+) -----
	opt := off
	binary.LittleEndian.PutUint16(buf[opt+0:], 0x020b) // Magic = PE32+
	buf[opt+2] = 14                                    // MajorLinkerVersion (cosmetic)
	buf[opt+3] = 0
	binary.LittleEndian.PutUint32(buf[opt+4:], stubRawSize) // SizeOfCode (the .stub section)
	binary.LittleEndian.PutUint32(buf[opt+8:], 0)           // SizeOfInitializedData
	binary.LittleEndian.PutUint32(buf[opt+12:], 0)          // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(buf[opt+16:], entryRVA)   // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(buf[opt+20:], stubRVA)    // BaseOfCode
	// PE32+ omits BaseOfData. ImageBase is at +24 and 8 bytes wide.
	binary.LittleEndian.PutUint64(buf[opt+24:], defaultImageBase)
	binary.LittleEndian.PutUint32(buf[opt+32:], sectionAlignment)
	binary.LittleEndian.PutUint32(buf[opt+36:], fileAlignment)
	// Major/Minor OS/Image/Subsystem versions left zero
	binary.LittleEndian.PutUint32(buf[opt+56:], sizeOfImage)
	binary.LittleEndian.PutUint32(buf[opt+60:], sizeOfHeaders)
	// CheckSum +64 left zero (firmware does not enforce it)
	binary.LittleEndian.PutUint16(buf[opt+68:], efiSubsystem)
	// DllCharacteristics +70 left zero
	binary.LittleEndian.PutUint64(buf[opt+72:], 0x100000) // SizeOfStackReserve = 1 MiB
	binary.LittleEndian.PutUint64(buf[opt+80:], 0x100000) // SizeOfStackCommit
	binary.LittleEndian.PutUint64(buf[opt+88:], 0x100000) // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(buf[opt+96:], 0x100000) // SizeOfHeapCommit
	// LoaderFlags +104 = 0
	binary.LittleEndian.PutUint32(buf[opt+108:], numDataDirs)
	// Data directories left zero (no exports/imports/reloc/etc. for the placeholder)
	off += optHeaderLen

	// ----- Section Table: .stub -----
	writeSectionHeader(buf[off:], stubSectionName,
		stubVirtualSize, stubRVA, stubRawSize, stubFileOff,
		scnCntCode|scnMemExecute|scnMemRead)
	off += sectionEntrySz

	// ----- Section data: .stub -----
	copy(buf[stubFileOff:], stubBody)

	return buf, nil
}

// writeSectionHeader fills one 40-byte IMAGE_SECTION_HEADER slot.
func writeSectionHeader(dst []byte, name string, vsize, rva, rsize, foff, chars uint32) {
	copy(dst[0:8], name)
	for i := len(name); i < 8; i++ {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[8:], vsize)
	binary.LittleEndian.PutUint32(dst[12:], rva)
	binary.LittleEndian.PutUint32(dst[16:], rsize)
	binary.LittleEndian.PutUint32(dst[20:], foff)
	// PointerToRelocations / LineNumbers + counts: zero (image section).
	binary.LittleEndian.PutUint32(dst[36:], chars)
}

func alignUp32(v, align uint32) uint32 {
	if align == 0 {
		return v
	}
	rem := v % align
	if rem == 0 {
		return v
	}
	return v + (align - rem)
}

// ReadPayload locates the .payload section in a packed PE32+ image,
// strips the wire header, and returns the raw compressed body plus
// the metadata stamped at pack time. It is the inverse of Pack's
// envelope assembly, used by host tests today and by the runtime
// stub (PR2) tomorrow. It does NOT decompress — the caller pairs it
// with a bodyCodec.Decode for the appropriate algorithm.
func ReadPayload(pe []byte) (algo string, uncompressedSize uint64, body []byte, err error) {
	sec, err := findSection(pe, payloadSectionName)
	if err != nil {
		return "", 0, nil, err
	}
	if len(sec) < payloadHeaderSize {
		return "", 0, nil, fmt.Errorf("efipack: .payload too short (%d bytes)", len(sec))
	}
	if string(sec[0:4]) != payloadMagic {
		return "", 0, nil, fmt.Errorf("efipack: .payload bad magic %q", sec[0:4])
	}
	algo = string(sec[4:8])
	uncompressedSize = binary.LittleEndian.Uint64(sec[8:16])
	compressedSize := binary.LittleEndian.Uint64(sec[16:24])
	if uint64(len(sec))-payloadHeaderSize < compressedSize {
		return "", 0, nil, fmt.Errorf("efipack: .payload truncated (header says %d compressed, have %d)",
			compressedSize, len(sec)-payloadHeaderSize)
	}
	body = sec[payloadHeaderSize : payloadHeaderSize+int(compressedSize)]
	return algo, uncompressedSize, body, nil
}

// findSection returns the raw bytes of the named section inside pe.
// Walks the section table directly so it works on any PE32 / PE32+
// regardless of machine. Used by ReadPayload and by the round-trip
// tests.
func findSection(pe []byte, name string) ([]byte, error) {
	if len(pe) < 0x40 {
		return nil, fmt.Errorf("efipack: pe too short (%d bytes)", len(pe))
	}
	if pe[0] != 'M' || pe[1] != 'Z' {
		return nil, fmt.Errorf("efipack: not a PE/MZ image")
	}
	elfanew := binary.LittleEndian.Uint32(pe[0x3C:])
	if uint64(elfanew)+4+coffHeaderLen > uint64(len(pe)) {
		return nil, fmt.Errorf("efipack: truncated PE header")
	}
	if string(pe[elfanew:elfanew+4]) != peSignature {
		return nil, fmt.Errorf("efipack: missing PE signature")
	}
	coffOff := int(elfanew) + peSigSize
	numSections := binary.LittleEndian.Uint16(pe[coffOff+2:])
	sizeOfOpt := binary.LittleEndian.Uint16(pe[coffOff+16:])
	secTableStart := coffOff + coffHeaderLen + int(sizeOfOpt)
	if secTableStart+int(numSections)*sectionEntrySz > len(pe) {
		return nil, fmt.Errorf("efipack: truncated section table")
	}
	for i := 0; i < int(numSections); i++ {
		off := secTableStart + i*sectionEntrySz
		secName := trimNUL(pe[off : off+8])
		if secName != name {
			continue
		}
		vsize := binary.LittleEndian.Uint32(pe[off+8:])
		rsize := binary.LittleEndian.Uint32(pe[off+16:])
		foff := binary.LittleEndian.Uint32(pe[off+20:])
		// VirtualSize is the truthful size of the body; RawSize is
		// padded to FileAlignment.
		size := vsize
		if size > rsize {
			size = rsize
		}
		if uint64(foff)+uint64(size) > uint64(len(pe)) {
			return nil, fmt.Errorf("efipack: section %q points past end of file", name)
		}
		return pe[foff : foff+size], nil
	}
	return nil, fmt.Errorf("efipack: section %q not found", name)
}

// trimNUL returns the leading NUL-free prefix of b interpreted as a
// string. PE section names are 8-byte NUL-padded.
func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
