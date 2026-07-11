// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package efipack

import (
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"io"

	"github.com/go-compressions/lz4"
	"github.com/go-compressions/lzfse"
)

// Compressor is the body-compression algorithm used by Pack.
//
// The default is Flate; it costs zero additional bytes in the
// decompressor stub because cloud-boot binaries already link
// compress/gzip via M6.1's embedded payloads and M7's OCI manifest
// handling. Alternatives (LZFSE, LZ4) can be wired in by adding a
// constant + case in switchCompressor.
type Compressor int

const (
	// Flate uses stdlib compress/flate. Default; zero stub cost.
	Flate Compressor = iota
	// LZFSE uses github.com/go-compressions/lzfse. Best raw ratio. The
	// shipped per-arch runtime stubs decode FLAT, LZ4 and LZFSE, so an
	// LZFSE-packed EFI boots and hands off on every supported arch
	// (verified under QEMU+OVMF on amd64/arm64).
	LZFSE
	// LZ4 uses github.com/go-compressions/lz4's pure-Go block codec —
	// the fastest decompressor of the three, at a lower ratio. Like
	// LZFSE, an LZ4-packed EFI boots on every supported arch: the
	// shipped runtime stubs decode the "LZ4 " algo tag natively.
	LZ4
)

// String returns a short stable name for the compressor.
func (c Compressor) String() string {
	switch c {
	case Flate:
		return "flate"
	case LZFSE:
		return "lzfse"
	case LZ4:
		return "lz4"
	default:
		return fmt.Sprintf("Compressor(%d)", int(c))
	}
}

// ErrCompressorNotImplemented is the sentinel switchCompressor
// returns for a valid Compressor constant that has no codec wired in
// the current build. As of v0.3.0 every defined Compressor (Flate,
// LZFSE, LZ4) is implemented host-side, so switchCompressor no longer
// returns it; the sentinel is retained as a stable part of the public
// API so callers that added a Compressor constant ahead of its codec
// can keep matching on it with errors.Is.
var ErrCompressorNotImplemented = errors.New("efipack: compressor not implemented in this build")

// bodyCodec is the internal compressor interface. Encode writes the
// compressed body to dst; Decode reverses it. StubBlobName returns the
// per-arch decompressor stub blob name PR2 will embed.
type bodyCodec interface {
	Encode(dst io.Writer, src []byte) error
	Decode(dst io.Writer, src []byte) error
	StubBlobName() string
}

// switchCompressor returns the bodyCodec for c, or
// ErrCompressorNotImplemented for currently-stubbed algorithms.
func switchCompressor(c Compressor, level int) (bodyCodec, error) {
	switch c {
	case Flate:
		return &flateCodec{level: level}, nil
	case LZFSE:
		// LZFSE is a single-mode algorithm with no notion of a
		// compression level; the level argument is intentionally
		// ignored here.
		return lzfseCodec{}, nil
	case LZ4:
		// LZ4's block format has no compression-level knob, so the
		// level argument is intentionally ignored here (as for LZFSE).
		return lz4Codec{}, nil
	default:
		return nil, fmt.Errorf("efipack: unknown compressor %d", int(c))
	}
}

// flateCodec is the stdlib compress/flate implementation.
type flateCodec struct{ level int }

// Encode writes a flate-compressed stream of src to dst.
func (f *flateCodec) Encode(dst io.Writer, src []byte) error {
	lvl := f.level
	if lvl == 0 {
		lvl = flate.DefaultCompression
	}
	zw, err := flate.NewWriter(dst, lvl)
	if err != nil {
		return fmt.Errorf("efipack: flate writer: %w", err)
	}
	if _, err := zw.Write(src); err != nil {
		_ = zw.Close()
		return fmt.Errorf("efipack: flate write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("efipack: flate close: %w", err)
	}
	return nil
}

// Decode reads a flate-compressed src and writes the inflated bytes to
// dst. Used by the host-side round-trip tests; PR2's runtime stub will
// re-implement this against its own (TamaGo-friendly) inflate.
func (f *flateCodec) Decode(dst io.Writer, src []byte) error {
	zr := flate.NewReader(bytes.NewReader(src))
	defer zr.Close()
	if _, err := io.Copy(dst, zr); err != nil {
		return fmt.Errorf("efipack: flate decode: %w", err)
	}
	return nil
}

// StubBlobName returns the per-arch decompressor stub blob name.
// PR2 will commit the actual blobs under stub/blobs/ and embed them
// via //go:embed.
func (f *flateCodec) StubBlobName() string {
	return "decompress-flate"
}

// lzfseCodec is the github.com/go-compressions/lzfse implementation
// of bodyCodec. LZFSE is a single-mode algorithm (no level knob);
// switchCompressor discards Options.Level on the LZFSE path.
//
// The runtime decompressor stubs embedded under stub/blobs/<arch>.efi.bin
// decode LZFSE natively (via the same go-compressions/lzfse package used
// here), so an LZFSE-packed EFI boots and hands off on every supported
// arch. Requires go-compressions/lzfse >= v0.2.0, which fixes a
// multi-block round-trip defect present in v0.1.0.
type lzfseCodec struct{}

// Encode writes an LZFSE-compressed stream of src to dst.
func (lzfseCodec) Encode(dst io.Writer, src []byte) error {
	enc, err := lzfse.Compress(src)
	if err != nil {
		return fmt.Errorf("efipack: lzfse compress: %w", err)
	}
	if _, err := dst.Write(enc); err != nil {
		return fmt.Errorf("efipack: lzfse write: %w", err)
	}
	return nil
}

// Decode reads an LZFSE-compressed src and writes the decoded bytes
// to dst. Used by host-side round-trip tests; the runtime stub will
// re-implement decode against its own TamaGo-friendly LZFSE inflate
// in a future PR.
func (lzfseCodec) Decode(dst io.Writer, src []byte) error {
	dec, err := lzfse.Decompress(src)
	if err != nil {
		return fmt.Errorf("efipack: lzfse decompress: %w", err)
	}
	if _, err := dst.Write(dec); err != nil {
		return fmt.Errorf("efipack: lzfse write: %w", err)
	}
	return nil
}

// StubBlobName returns the per-arch decompressor stub blob name the
// future LZFSE-aware runtime stub will register under. The blobs do
// NOT exist yet (see lzfseCodec doc comment).
func (lzfseCodec) StubBlobName() string {
	return "decompress-lzfse"
}

// lz4Codec implements bodyCodec via github.com/go-compressions/lz4's
// pure-Go LZ4 block format. LZ4 favours decompression speed over
// ratio, which suits a runtime stub that wants the smallest, simplest
// inflate loop. Like LZFSE it has no compression-level knob, so
// switchCompressor discards Options.Level on the LZ4 path.
//
// The .payload body is a single raw LZ4 block — no inner size prefix
// — mirroring the FLAT convention where the body is exactly the codec
// stream and nothing else. DecompressBlock recovers the precise output
// length by parsing the block, so Decode passes a zero capacity hint
// and lets the decoder grow its buffer; the runtime stub instead
// passes the CBP0 header's uncompressed size as the hint to avoid the
// reallocations.
//
// The runtime decompressor stubs embedded under stub/blobs/<arch>.efi.bin
// decode the "LZ4 " algo tag natively (via the same go-compressions/lz4
// DecompressBlock used here, seeded with the CBP0 uncompressed size), so
// an LZ4-packed EFI boots and hands off on every supported arch. Requires
// go-compressions/lz4 >= v0.1.1, which fixes a 64 KiB-distance encoder
// defect that produced undecodable blocks on larger inputs.
type lz4Codec struct{}

// Encode writes a raw LZ4 block of src to dst.
func (lz4Codec) Encode(dst io.Writer, src []byte) error {
	enc := lz4.CompressBlock(src)
	if _, err := dst.Write(enc); err != nil {
		return fmt.Errorf("efipack: lz4 write: %w", err)
	}
	return nil
}

// Decode reads a raw LZ4 block from src and writes the decoded bytes
// to dst. A zero capacity hint is passed to DecompressBlock, which
// grows its output buffer as it parses the block. Used by the
// host-side round-trip tests; the runtime stub re-implements decode
// against the same go-compressions/lz4 block loop, seeded with the
// CBP0 uncompressed size.
func (lz4Codec) Decode(dst io.Writer, src []byte) error {
	dec, err := lz4.DecompressBlock(src, 0)
	if err != nil {
		return fmt.Errorf("efipack: lz4 decompress: %w", err)
	}
	if _, err := dst.Write(dec); err != nil {
		return fmt.Errorf("efipack: lz4 write: %w", err)
	}
	return nil
}

// StubBlobName returns the per-arch decompressor stub blob name an
// LZ4-aware runtime stub would register under. No LZ4 blob ships yet
// (see lz4Codec doc comment).
func (lz4Codec) StubBlobName() string {
	return "decompress-lz4"
}
