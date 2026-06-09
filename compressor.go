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
	// LZFSE uses github.com/go-compressions/lzfse. Optional; the
	// decompressor stub grows by ~100-200 KiB. Not yet wired (PR2).
	LZFSE
	// LZ4 is reserved for a future tiny-payload optimisation.
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

// ErrCompressorNotImplemented is returned by switchCompressor for
// algorithms that are valid Compressor constants but not yet wired in
// this PR. PR2 implements LZFSE; LZ4 is reserved for later.
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
		return nil, ErrCompressorNotImplemented
	case LZ4:
		return nil, ErrCompressorNotImplemented
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
