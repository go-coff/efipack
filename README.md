<p align="center"><img src="https://raw.githubusercontent.com/go-coff/brand/main/social/go-coff-efipack.png" alt="go-coff/efipack" width="720"></p>

# go-coff/efipack

[![CI](https://github.com/go-coff/efipack/actions/workflows/ci.yml/badge.svg)](https://github.com/go-coff/efipack/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-coff/efipack.svg)](https://pkg.go.dev/github.com/go-coff/efipack)

Pure-Go library that compresses PE32+/EFI binaries into a self-extracting
PE32+/EFI image — the UPX-equivalent that does not exist anywhere else for
this format. Designed to mitigate the EDK2 OVMF amd64 CpuPageTableLib `#GP`
that fires on `LoadImage` / `StartImage` of sufficiently large EFI binaries
(cloud-boot M6.2 milestone).

## Status — PR1 (library skeleton)

This revision ships the **host side** only:

- compression API (`Pack`, `Options`, `PackResult`),
- PE32+/EFI envelope assembly (DOS stub + PE signature + COFF + optional
  header + section table + `.stub` placeholder + `.payload` body),
- arch detection (amd64, arm64, riscv64, loong64),
- a swappable body compressor (default `Flate`; `LZFSE`, `LZ4` reserved),
- round-trip tests proving the bytes in `.payload` decompress back to the
  original input.

The output is **not yet a runnable EFI**: the `.stub` section contains a
`TODO_STUB` placeholder. The runtime per-arch decompressor stub lands in
**PR2**; the `pectl pack` CLI subcommand and the cross-arch boot-smoke
matrix land in **PR3**.

## API surface

```go
import "github.com/go-coff/efipack"

// Detect the architecture of an input PE32+ from its COFF header.
arch, err := efipack.InferArch(peBytes)
// arch ∈ {AmdArch, ArmArch, RiscvArch, LoongArch}

// Pack a PE32+ binary into a self-extracting envelope.
in, _ := os.Open("BOOTX64.EFI")
out, _ := os.Create("BOOTX64-packed.EFI")
res, err := efipack.Pack(in, out, efipack.Options{
    Compressor: efipack.Flate, // default; zero stub cost
    Level:      0,             // 0 → codec default
})
// res.OriginalSize, res.CompressedSize, res.PackedSize, res.Arch, res.Compressor
```

| Type / constant | Purpose |
| --- | --- |
| `Pack(in, out, opts) (PackResult, error)` | host-side compress + envelope |
| `Options{Compressor, Level}` | knobs; zero value = Flate at default level |
| `PackResult{OriginalSize, CompressedSize, PackedSize, Compressor, Arch}` | summary |
| `Compressor` (`Flate` / `LZFSE` / `LZ4`) | algorithm switch |
| `Arch` (`AmdArch` / `ArmArch` / `RiscvArch` / `LoongArch`) | PE machine |
| `InferArch(pe) (Arch, error)` | read COFF.Machine without `debug/pe` (works on loong64) |
| `ReadPayload(pe) (algo, uncompressedSize, body, err)` | inverse of Pack's envelope; used by host tests and by PR2's runtime stub |
| `ErrCompressorNotImplemented` | sentinel for codecs that aren't wired yet — `LZ4` only as of M6.2 PR4 |

### `.payload` wire format

```
.payload section body:
  magic         [4]byte   "CBP0"   — cloud-boot pack v0
  algo          [4]byte   "FLAT" | "LZFS" | "LZ4 "
  uncompressed  uint64    little-endian — host-input size in bytes
  compressed    uint64    little-endian — body size in bytes
  body          [N]byte   exactly N=compressed bytes; codec-specific stream
```

PR2's runtime stub reads this header, allocates exactly the right number
of `EfiBootServicesCode` pages, decompresses, then chain-loads via
`gBS->LoadImage` + `gBS->StartImage`.

## Why Flate as the default?

The original M6.2 design picked LZFSE on raw ratio (40.13% vs 39.11%).
After review we pivoted: cloud-boot binaries already link `compress/gzip`
via M6.1 embeds and M7 OCI manifest handling, so the Flate-based stub
adds **zero bytes** vs LZFSE's ~100-200 KiB cost. The 1-point ratio gap
is negligible against the ~5 MiB binaries we are compressing. LZFSE
remains pluggable via the `Compressor` enum for cases where the host has
a larger budget than the cloud-boot baseline.

## LZFSE — host-side only (M6.2 PR4)

`Compressor = LZFSE` was wired in v0.2.0 via
[`github.com/go-compressions/lzfse`](https://github.com/go-compressions/lzfse).
It works end-to-end on the **host side**: `Pack` produces a structurally
valid PE32+ envelope whose `.payload` decodes back to the original input
byte-for-byte. **However**, the embedded per-arch runtime decompressor
stubs (`stub/blobs/<arch>.efi.bin`) are still Flate-only — a packed binary
produced with `Compressor = LZFSE` will NOT boot under firmware because
the stub it inherits doesn't know how to decode `LZFS`. Rebuilding the
runtime stubs with an LZFSE inflate (and re-embedding them) is a deferred
follow-up; meanwhile use `Compressor = Flate` for runnable packed EFIs.

## Dependencies

- [`github.com/go-coff/peln`](https://github.com/go-coff/peln) — PE32+
  section-append (used to attach `.payload` to the envelope).
- [`github.com/go-compressions/lzfse`](https://github.com/go-compressions/lzfse)
  — pure-Go LZFSE/LZVN codec for the host-side `LZFSE` compressor (M6.2 PR4).

No CGO, no vendoring, stdlib-only otherwise.

## License

[BSD 3-Clause](LICENSE).
