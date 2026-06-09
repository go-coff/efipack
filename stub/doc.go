// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

// Package stub embeds the per-arch self-extracting decompressor blobs
// produced by github.com/cloud-boot/tamago-uefi/cmd/efipackstub.
//
// Each blob is a complete PE32+/EFI image whose entry point parses
// the envelope PE's `.payload` section (cloud-boot pack v0 wire
// format), decompresses it, and chain-boots the original payload via
// gBS->LoadImage + gBS->StartImage. efipack/pack.go uses the blob
// for the matching architecture as the envelope base PE, then
// appends `.payload` via peln/appender. The result is a runnable
// self-extracting PE32+ that the firmware can load and execute as a
// drop-in replacement for the original (unpacked) payload.
//
// M6.2 PR2 ships amd64 only; arm64 / riscv64 / loong64 land in a
// follow-up sprint once the same chain-boot mechanism is validated
// per-arch.
//
// The blobs are pure data — they describe the firmware-side stub
// binary, not the host build's architecture — so this package
// compiles on every host (no GOOS/GOARCH build constraints).
package stub
