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

func TestSwitchCompressorLZFSENotImplemented(t *testing.T) {
	_, err := switchCompressor(LZFSE, 0)
	if !errors.Is(err, ErrCompressorNotImplemented) {
		t.Fatalf("switchCompressor(LZFSE) = %v, want ErrCompressorNotImplemented", err)
	}
}

func TestSwitchCompressorLZ4NotImplemented(t *testing.T) {
	_, err := switchCompressor(LZ4, 0)
	if !errors.Is(err, ErrCompressorNotImplemented) {
		t.Fatalf("switchCompressor(LZ4) = %v, want ErrCompressorNotImplemented", err)
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
