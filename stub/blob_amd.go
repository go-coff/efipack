// Copyright (c) 2026 The go-coff Authors. All rights reserved.
// Use of this source code is governed by a BSD-3-Clause license that
// can be found in the LICENSE file.

package stub

import _ "embed"

// AMD64 is the BOOTX64-EFIPACKSTUB.EFI built from
// github.com/cloud-boot/tamago-uefi/cmd/efipackstub via
// `task efistub:amd64`. The blob is a full PE32+ image: efipack's
// Pack appends a `.payload` section to it (preserving every existing
// section's RVA and file offset) to produce the envelope PE.
//
// The blob is host-arch-independent — it ships as a byte slice and is
// only ever interpreted as PE32+ at firmware load time, so we embed it
// from every host build (Linux/Darwin amd64 OR arm64 etc).
//
//go:embed blobs/amd64.efi.bin
var AMD64 []byte
