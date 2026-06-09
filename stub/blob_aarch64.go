// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package stub

import _ "embed"

// ARM64 is the BOOTAA64-EFIPACKSTUB.EFI built from
// github.com/cloud-boot/tamago-uefi/cmd/efipackstub via
// `task efistub:arm64`. The blob is a full PE32+ image (PE COFF
// Machine = 0xaa64): efipack's Pack appends a `.payload` section to
// it (preserving every existing section's RVA and file offset) to
// produce the envelope PE.
//
// The blob is host-arch-independent — it ships as a byte slice and is
// only ever interpreted as PE32+ at firmware load time, so we embed it
// from every host build (Linux/Darwin amd64 OR arm64 etc).
//
// The arm64 stub uses the same "option 2" SimpleFileSystem re-read
// path as the amd64 stub: it walks the EFI_LOADED_IMAGE_PROTOCOL ->
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL -> EFI_FILE_PROTOCOL chain to
// recover its own on-disk PE bytes, locates `.payload` at its
// PointerToRawData offset, decompresses, and chain-boots via
// gBS->LoadImage + gBS->StartImage. On arm64 this works on first
// attempt because the firmware-mapping quirk that blocks the amd64
// path doesn't reproduce on aarch64-virt.
//
//go:embed blobs/arm64.efi.bin
var ARM64 []byte
