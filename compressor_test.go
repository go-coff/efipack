// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package efipack

import (
	"bytes"
	"compress/flate"
	"errors"
	"strings"
	"testing"
)

func TestCompressorString(t *testing.T) {
	cases := []struct {
		c    Compressor
		want string
	}{
		{Flate, "flate"},
		{LZFSE, "lzfse"},
		{LZ4, "lz4"},
		{Compressor(99), "Compressor(99)"},
	}
	for _, c := range cases {
		if got := c.c.String(); got != c.want {
			t.Errorf("Compressor(%d).String() = %q, want %q", int(c.c), got, c.want)
		}
	}
}

func TestSwitchCompressorFlateRoundTrip(t *testing.T) {
	codec, err := switchCompressor(Flate, 0)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	if name := codec.StubBlobName(); name != "decompress-flate" {
		t.Fatalf("StubBlobName = %q, want decompress-flate", name)
	}

	// Use a payload large enough to exercise the deflate window — a
	// trivially-short input round-trips even without compression.
	src := bytes.Repeat([]byte("efipack flate round-trip "), 4096)

	var enc bytes.Buffer
	if err := codec.Encode(&enc, src); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if enc.Len() >= len(src) {
		t.Fatalf("Encode produced %d bytes for %d input; expected compression", enc.Len(), len(src))
	}

	var dec bytes.Buffer
	if err := codec.Decode(&dec, enc.Bytes()); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), src) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", dec.Len(), len(src))
	}
}

func TestSwitchCompressorFlateExplicitLevel(t *testing.T) {
	codec, err := switchCompressor(Flate, flate.BestCompression)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	src := []byte("hello flate level 9")
	var enc bytes.Buffer
	if err := codec.Encode(&enc, src); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var dec bytes.Buffer
	if err := codec.Decode(&dec, enc.Bytes()); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), src) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestSwitchCompressorFlateInvalidLevel(t *testing.T) {
	// flate.NewWriter accepts -2..9; anything outside that is rejected.
	codec, err := switchCompressor(Flate, 42)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	var enc bytes.Buffer
	if err := codec.Encode(&enc, []byte("x")); err == nil {
		t.Fatalf("Encode: want error for invalid level, got nil")
	}
}

func TestSwitchCompressorFlateDecodeMalformed(t *testing.T) {
	codec, err := switchCompressor(Flate, 0)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	var dec bytes.Buffer
	// Truncated/garbage stream -> the io.Copy in Decode surfaces the
	// flate.NewReader error.
	if err := codec.Decode(&dec, []byte{0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatalf("Decode: want error for malformed input, got nil")
	}
}

// TestLZFSEEncodeDecodeRoundTrip mirrors the flate round-trip: a
// large patterned payload encodes to fewer bytes than the input and
// decodes back to the original byte-for-byte. Also asserts
// switchCompressor(LZFSE) no longer returns ErrCompressorNotImplemented
// (M6.2 PR4 wired the real codec).
func TestLZFSEEncodeDecodeRoundTrip(t *testing.T) {
	codec, err := switchCompressor(LZFSE, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZFSE): %v", err)
	}
	if errors.Is(err, ErrCompressorNotImplemented) {
		t.Fatalf("switchCompressor(LZFSE) still returns ErrCompressorNotImplemented")
	}
	if name := codec.StubBlobName(); name != "decompress-lzfse" {
		t.Fatalf("StubBlobName = %q, want decompress-lzfse", name)
	}

	// Same shape as the flate round-trip: a large repeating payload
	// guarantees a compression ratio strictly < 1 so we exercise the
	// codec's match-finding, not just its passthrough path.
	src := bytes.Repeat([]byte("efipack lzfse round-trip "), 4096)

	var enc bytes.Buffer
	if err := codec.Encode(&enc, src); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if enc.Len() >= len(src) {
		t.Fatalf("Encode produced %d bytes for %d input; expected compression", enc.Len(), len(src))
	}

	var dec bytes.Buffer
	if err := codec.Decode(&dec, enc.Bytes()); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), src) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", dec.Len(), len(src))
	}
}

// TestLZFSEIgnoresLevel asserts that switchCompressor(LZFSE, level)
// returns a working codec irrespective of the level argument — LZFSE
// is a single-mode algorithm with no compression-level knob.
func TestLZFSEIgnoresLevel(t *testing.T) {
	for _, lvl := range []int{-2, 0, 1, 9, 42} {
		codec, err := switchCompressor(LZFSE, lvl)
		if err != nil {
			t.Fatalf("switchCompressor(LZFSE, %d): %v", lvl, err)
		}
		src := []byte("hello lzfse no levels")
		var enc bytes.Buffer
		if err := codec.Encode(&enc, src); err != nil {
			t.Fatalf("Encode(level=%d): %v", lvl, err)
		}
		var dec bytes.Buffer
		if err := codec.Decode(&dec, enc.Bytes()); err != nil {
			t.Fatalf("Decode(level=%d): %v", lvl, err)
		}
		if !bytes.Equal(dec.Bytes(), src) {
			t.Fatalf("round-trip mismatch at level=%d", lvl)
		}
	}
}

// TestLZFSEDecodeMalformed exercises the Decode error path: bogus
// input bytes that don't begin with a valid LZFSE block magic should
// surface an error rather than a silent empty output.
func TestLZFSEDecodeMalformed(t *testing.T) {
	codec, err := switchCompressor(LZFSE, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZFSE): %v", err)
	}
	var dec bytes.Buffer
	if err := codec.Decode(&dec, []byte{0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatalf("Decode: want error for malformed input, got nil")
	}
}

// TestLZFSEEncodeWriteError forces the dst-write error branch in
// lzfseCodec.Encode. lzfse.Compress always succeeds for small inputs;
// the io.Writer.Write call after it is what surfaces the failure.
func TestLZFSEEncodeWriteError(t *testing.T) {
	codec, err := switchCompressor(LZFSE, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZFSE): %v", err)
	}
	if err := codec.Encode(failingWriter{}, []byte("hi")); err == nil {
		t.Fatalf("Encode(failingWriter): want error, got nil")
	}
}

// TestLZFSEDecodeWriteError forces the dst-write error branch in
// lzfseCodec.Decode. We feed a valid LZFSE stream so the decoder
// succeeds, then the io.Writer.Write call fails.
func TestLZFSEDecodeWriteError(t *testing.T) {
	codec, err := switchCompressor(LZFSE, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZFSE): %v", err)
	}
	var enc bytes.Buffer
	if err := codec.Encode(&enc, []byte("hello lzfse decode write error")); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := codec.Decode(failingWriter{}, enc.Bytes()); err == nil {
		t.Fatalf("Decode(failingWriter): want error, got nil")
	}
}

// TestLZ4EncodeDecodeRoundTrip mirrors the flate/lzfse round-trips: a
// large patterned payload encodes to fewer bytes than the input and
// decodes back to the original byte-for-byte. Also asserts
// switchCompressor(LZ4) no longer returns ErrCompressorNotImplemented
// (v0.3.0 wired the pure-Go go-compressions/lz4 block codec).
func TestLZ4EncodeDecodeRoundTrip(t *testing.T) {
	codec, err := switchCompressor(LZ4, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZ4): %v", err)
	}
	if errors.Is(err, ErrCompressorNotImplemented) {
		t.Fatalf("switchCompressor(LZ4) still returns ErrCompressorNotImplemented")
	}
	if name := codec.StubBlobName(); name != "decompress-lz4" {
		t.Fatalf("StubBlobName = %q, want decompress-lz4", name)
	}

	src := bytes.Repeat([]byte("efipack lz4 round-trip "), 4096)

	var enc bytes.Buffer
	if err := codec.Encode(&enc, src); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if enc.Len() >= len(src) {
		t.Fatalf("Encode produced %d bytes for %d input; expected compression", enc.Len(), len(src))
	}

	var dec bytes.Buffer
	if err := codec.Decode(&dec, enc.Bytes()); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), src) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", dec.Len(), len(src))
	}
}

// TestLZ4IgnoresLevel asserts switchCompressor(LZ4, level) returns a
// working codec irrespective of the level argument — the LZ4 block
// format has no compression-level knob.
func TestLZ4IgnoresLevel(t *testing.T) {
	for _, lvl := range []int{-2, 0, 1, 9, 42} {
		codec, err := switchCompressor(LZ4, lvl)
		if err != nil {
			t.Fatalf("switchCompressor(LZ4, %d): %v", lvl, err)
		}
		src := []byte("hello lz4 no levels")
		var enc bytes.Buffer
		if err := codec.Encode(&enc, src); err != nil {
			t.Fatalf("Encode(level=%d): %v", lvl, err)
		}
		var dec bytes.Buffer
		if err := codec.Decode(&dec, enc.Bytes()); err != nil {
			t.Fatalf("Decode(level=%d): %v", lvl, err)
		}
		if !bytes.Equal(dec.Bytes(), src) {
			t.Fatalf("round-trip mismatch at level=%d", lvl)
		}
	}
}

// TestLZ4DecodeMalformed exercises the Decode error path: a token
// requesting an extended literal length whose continuation bytes run
// off the end of the block surfaces the go-compressions/lz4 corrupt
// error rather than a silent empty output.
func TestLZ4DecodeMalformed(t *testing.T) {
	codec, err := switchCompressor(LZ4, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZ4): %v", err)
	}
	var dec bytes.Buffer
	if err := codec.Decode(&dec, []byte{0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatalf("Decode: want error for malformed input, got nil")
	}
}

// TestLZ4EncodeWriteError forces the dst-write error branch in
// lz4Codec.Encode: CompressBlock always succeeds, so the failure comes
// from the io.Writer.Write that follows it.
func TestLZ4EncodeWriteError(t *testing.T) {
	codec, err := switchCompressor(LZ4, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZ4): %v", err)
	}
	if err := codec.Encode(failingWriter{}, []byte("hi")); err == nil {
		t.Fatalf("Encode(failingWriter): want error, got nil")
	}
}

// TestLZ4DecodeWriteError forces the dst-write error branch in
// lz4Codec.Decode: a valid block decodes cleanly, then the
// io.Writer.Write fails.
func TestLZ4DecodeWriteError(t *testing.T) {
	codec, err := switchCompressor(LZ4, 0)
	if err != nil {
		t.Fatalf("switchCompressor(LZ4): %v", err)
	}
	var enc bytes.Buffer
	if err := codec.Encode(&enc, []byte("hello lz4 decode write error")); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := codec.Decode(failingWriter{}, enc.Bytes()); err == nil {
		t.Fatalf("Decode(failingWriter): want error, got nil")
	}
}

// failingWriter returns an error from every Write. Used to force the
// flateCodec.Encode error paths (write + close).
type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errFailingWriter }

var errFailingWriter = errors.New("failing writer")

func TestSwitchCompressorFlateEncodeWriteAndCloseErrors(t *testing.T) {
	codec, err := switchCompressor(Flate, 0)
	if err != nil {
		t.Fatalf("switchCompressor: %v", err)
	}
	// Large payload guarantees the internal flate buffer flushes
	// during Write, so the write error surfaces from Write rather
	// than waiting for Close. Both paths funnel through the same
	// error wrapper.
	big := bytes.Repeat([]byte("x"), 1<<20)
	if err := codec.Encode(failingWriter{}, big); err == nil {
		t.Fatalf("Encode(failingWriter): want error, got nil")
	}
	// Small payload only flushes at Close → exercises the close-error
	// branch.
	if err := codec.Encode(failingWriter{}, []byte("hi")); err == nil {
		t.Fatalf("Encode(failingWriter, small): want error, got nil")
	}
}

func TestSwitchCompressorUnknown(t *testing.T) {
	_, err := switchCompressor(Compressor(99), 0)
	if err == nil {
		t.Fatalf("switchCompressor(99): want error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown compressor") {
		t.Fatalf("switchCompressor(99) error = %q, want substring %q", err.Error(), "unknown compressor")
	}
}
