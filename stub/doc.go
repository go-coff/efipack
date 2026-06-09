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
// M6.2 PR2 ships stubs for all four EFI machines (amd64, arm64,
// riscv64, loong64). arm64/riscv64/loong64 are GREEN under the live
// QEMU+EDK2 smoke matrix; amd64 has a runtime crash inside the stub
// and is tracked on the m6-2-pr2-amd64-wip branch for follow-up.
//
// The blobs are pure data — they describe the firmware-side stub
// binary, not the host build's architecture — so this package
// compiles on every host (no GOOS/GOARCH build constraints).
package stub
