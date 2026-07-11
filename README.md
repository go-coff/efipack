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

### Bootability matrix

The embedded per-arch runtime stubs decode **all three** algorithms
(`FLAT` / `LZ4 ` / `LZFS`), so a packed EFI produced with any `Compressor`
boots and hands off. Verified end-to-end under QEMU+OVMF by packing a
chained payload and matching its serial marker on successful decompress +
`gBS->LoadImage` / `gBS->StartImage`:

| Arch | Runtime stub | FLAT | LZ4 | LZFSE |
| --- | --- | --- | --- | --- |
| arm64 (`0xaa64`) | embedded | **QEMU+OVMF ✓** | **QEMU+OVMF ✓** | **QEMU+OVMF ✓** |
| amd64 (`0x8664`) | embedded | **QEMU+OVMF ✓** | **QEMU+OVMF ✓** | **QEMU+OVMF ✓** |
| riscv64 (`0x5064`) | embedded | boots under QEMU+EDK2 smoke; PE-structural in CI | same stub path | same stub path |
| loong64 (`0x6264`) | embedded | boots under QEMU+EDK2 smoke; PE-structural in CI | same stub path | same stub path |

The earlier amd64 `#UD`-on-entry defect no longer reproduces: the current
stub (rebuilt on the R-amd64f cpuinit `heapReserve` anchoring) boots
cleanly under the patched OVMF used by the smoke harness.

LZ4/LZFSE bootability requires `go-compressions/lz4 >= v0.1.1` and
`go-compressions/lzfse >= v0.2.0`; earlier releases had round-trip defects
(a 64 KiB-distance LZ4 encoder bug and an LZFSE multi-block bug) that
produced undecodable bodies on larger real inputs.

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
of `EfiBootServicesCode` pages, decompresses according to the algo tag
(`FLAT` / `LZ4 ` / `LZFS`), then chain-loads via `gBS->LoadImage` +
`gBS->StartImage`.

## Why Flate as the default?

The original M6.2 design picked LZFSE on raw ratio (40.13% vs 39.11%).
After review we pivoted: cloud-boot binaries already link `compress/gzip`
via M6.1 embeds and M7 OCI manifest handling, so the Flate-based stub
adds **zero bytes** vs LZFSE's ~100-200 KiB cost. The 1-point ratio gap
is negligible against the ~5 MiB binaries we are compressing. LZFSE
remains pluggable via the `Compressor` enum for cases where the host has
a larger budget than the cloud-boot baseline.

## LZFSE & LZ4 — bootable

`Compressor = LZFSE` (via
[`go-compressions/lzfse`](https://github.com/go-compressions/lzfse), best
ratio) and `Compressor = LZ4` (via
[`go-compressions/lz4`](https://github.com/go-compressions/lz4)'s pure-Go
block format, fastest decompress) work end-to-end: `Pack` produces a
structurally valid PE32+ envelope whose `.payload` decodes back to the
original input byte-for-byte, and the embedded per-arch runtime stubs
decode the matching `LZFS` / `LZ4 ` tag natively — so the packed EFI boots
and hands off under firmware, just like `FLAT`. This is verified under
QEMU+OVMF on amd64 and arm64 (see the bootability matrix above).

Both paths require the fixed codec releases (`go-compressions/lz4 >=
v0.1.1`, `go-compressions/lzfse >= v0.2.0`); the earlier tags round-tripped
small inputs in their own test suites but produced undecodable bodies on
larger real binaries (a 64 KiB match-distance LZ4 encoder bug and an LZFSE
multi-block bug), which is why the stubs previously shipped `FLAT`-only.
`Flate` remains the default for its zero incremental stub cost.

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
