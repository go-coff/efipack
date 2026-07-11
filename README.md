<p align="center"><img src="https://raw.githubusercontent.com/go-coff/brand/main/social/go-coff-efipack.png" alt="go-coff/efipack" width="720"></p>

# go-coff/efipack

[![CI](https://github.com/go-coff/efipack/actions/workflows/ci.yml/badge.svg)](https://github.com/go-coff/efipack/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-coff/efipack.svg)](https://pkg.go.dev/github.com/go-coff/efipack)

Pure-Go library that compresses PE32+/EFI binaries into a self-extracting
PE32+/EFI image — the UPX-equivalent that does not exist anywhere else for
this format. Designed to mitigate the EDK2 OVMF amd64 CpuPageTableLib `#GP`
that fires on `LoadImage` / `StartImage` of sufficiently large EFI binaries
(cloud-boot M6.2 milestone).

## Status

The library ships:

- compression API (`Pack`, `Options`, `PackResult`),
- PE32+/EFI envelope assembly (DOS stub + PE signature + COFF + optional
  header + section table + real per-arch runtime decompressor `.stub` +
  `.payload` body),
- arch detection (amd64, arm64, riscv64, loong64),
- a swappable body compressor — `Flate` (default), `LZFSE`, and `LZ4`,
  all pure-Go and host-side complete,
- round-trip tests proving the bytes in `.payload` decompress back to the
  original input, plus PE-structural tests over the embedded stubs.

The `TODO_STUB` placeholder is gone: `Pack` uses a real embedded per-arch
self-extracting stub (`stub/blobs/<arch>.efi.bin`) as the envelope base,
so a **`Flate`-packed** binary is a genuinely runnable self-extracting
EFI. At firmware load time the stub recovers its own on-disk bytes, finds
`.payload`, decompresses, and chain-boots via `gBS->LoadImage` +
`gBS->StartImage`.

### Bootability matrix (`Compressor = Flate`)

| Arch | Runtime stub | Boot status |
| --- | --- | --- |
| arm64 (`0xaa64`) | embedded | **OVMF/QEMU-verified** — packed EFI decompresses + hands off to the payload |
| riscv64 (`0x5064`) | embedded | boots under QEMU+EDK2 smoke; PE-structural in CI |
| loong64 (`0x6264`) | embedded | boots under QEMU+EDK2 smoke; PE-structural in CI |
| amd64 (`0x8664`) | embedded | **not bootable** — the stub faults on entry under OVMF with an X64 `#UD` (Invalid Opcode); a TamaGo-runtime bootstrap defect, tracked for a stub rebuild. Envelope is PE-valid and host-round-trips. |

`LZFSE` and `LZ4` are host-side only — see [below](#lzfse--lz4--host-side-only).

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
| `Compressor` (`Flate` / `LZFSE` / `LZ4`) | algorithm switch; all three wired |
| `Arch` (`AmdArch` / `ArmArch` / `RiscvArch` / `LoongArch`) | PE machine |
| `InferArch(pe) (Arch, error)` | read COFF.Machine without `debug/pe` (works on loong64) |
| `ReadPayload(pe) (algo, uncompressedSize, body, err)` | inverse of Pack's envelope; used by host tests and by the runtime stub |
| `ErrCompressorNotImplemented` | reserved public sentinel; no codec returns it now that all three are wired |

### `.payload` wire format

```
.payload section body:
  magic         [4]byte   "CBP0"   — cloud-boot pack v0
  algo          [4]byte   "FLAT" | "LZFS" | "LZ4 "
  uncompressed  uint64    little-endian — host-input size in bytes
  compressed    uint64    little-endian — body size in bytes
  body          [N]byte   exactly N=compressed bytes; codec-specific stream
```

The runtime stub reads this header, allocates exactly the right number
of `EfiBootServicesCode` pages, decompresses, then chain-loads via
`gBS->LoadImage` + `gBS->StartImage`. The shipped stubs dispatch on the
`FLAT` algo tag only (see below).

## Why Flate as the default?

The original M6.2 design picked LZFSE on raw ratio (40.13% vs 39.11%).
After review we pivoted: cloud-boot binaries already link `compress/gzip`
via M6.1 embeds and M7 OCI manifest handling, so the Flate-based stub
adds **zero bytes** vs LZFSE's ~100-200 KiB cost. The 1-point ratio gap
is negligible against the ~5 MiB binaries we are compressing. LZFSE
remains pluggable via the `Compressor` enum for cases where the host has
a larger budget than the cloud-boot baseline.

## LZFSE & LZ4 — host-side only

`Compressor = LZFSE` (via
[`go-compressions/lzfse`](https://github.com/go-compressions/lzfse), best
ratio) and `Compressor = LZ4` (via
[`go-compressions/lz4`](https://github.com/go-compressions/lz4)'s pure-Go
block format, fastest decompress) both work end-to-end on the **host
side**: `Pack` produces a structurally valid PE32+ envelope whose
`.payload` decodes back to the original input byte-for-byte, with the
matching `LZFS` / `LZ4 ` algo tag stamped in the CBP0 header.

**However**, the embedded per-arch runtime decompressor stubs
(`stub/blobs/<arch>.efi.bin`) dispatch on the `FLAT` tag only — a packed
binary produced with `LZFSE` or `LZ4` will NOT boot under firmware because
the stub does not decode that tag (verified: an `LZ4`-packed arm64 EFI
loads under OVMF, fails the `FLAT` check, and exits `EFI_ABORTED` without
handing off). Rebuilding the runtime stubs with an `LZFS` / `LZ4 ` decode
path (and re-embedding them) is gated on a TamaGo toolchain rebuild;
meanwhile use `Compressor = Flate` for runnable packed EFIs.

## Dependencies

- [`github.com/go-coff/peln`](https://github.com/go-coff/peln) — PE32+
  section-append (used to attach `.payload` to the envelope).
- [`github.com/go-compressions/lzfse`](https://github.com/go-compressions/lzfse)
  — pure-Go LZFSE/LZVN codec for the host-side `LZFSE` compressor.
- [`github.com/go-compressions/lz4`](https://github.com/go-compressions/lz4)
  — pure-Go LZ4 block codec for the host-side `LZ4` compressor.

No CGO, no vendoring, stdlib-only otherwise.

## License

[BSD 3-Clause](LICENSE).
