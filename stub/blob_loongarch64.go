// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package stub

import _ "embed"

// LoongArch64Blob is the BOOTLOONGARCH64-EFIPACKSTUB.EFI built from
// github.com/cloud-boot/tamago-uefi/cmd/efipackstub via
// `task efistub:loong64`. The blob is a full PE32+ image (PE COFF
// Machine = 0x6264): efipack's Pack appends a `.payload` section to
// it (preserving every existing section's RVA and file offset) to
// produce the envelope PE.
//
// The blob is host-arch-independent — it ships as a byte slice and is
// only ever interpreted as PE32+ at firmware load time, so we embed it
// from every host build (Linux/Darwin amd64 OR arm64 etc).
//
// The loong64 stub uses the same "option 2" SimpleFileSystem re-read
// path as the amd64 and arm64 stubs: it walks the
// EFI_LOADED_IMAGE_PROTOCOL -> EFI_SIMPLE_FILE_SYSTEM_PROTOCOL ->
// EFI_FILE_PROTOCOL chain to recover its own on-disk PE bytes,
// locates `.payload` at its PointerToRawData offset, decompresses,
// and chain-boots via gBS->LoadImage + gBS->StartImage.
//
// File-name suffix: `_loong64.go` would be interpreted by Go's build
// system as a GOARCH=loong64 constraint, which would prevent the blob
// from being embedded on amd64/arm64 hosts. The file is named after
// the PE Machine field's canonical UEFI spelling
// (IMAGE_FILE_MACHINE_LOONGARCH64) instead — the same trick
// `blob_aarch64.go` uses for the arm64 stub.
//
//go:embed blobs/loong64.efi.bin
var LoongArch64Blob []byte
