# ghidra-blackfin

A Ghidra 12 processor extension for the **classic Analog Devices Blackfin ISA**
(ADSP-BF53x and relatives). Ghidra has no Blackfin support; this module decodes
the whole instruction set, including multi-issue packets and hardware loops, and
gives every instruction p-code semantics, so the decompiler works on Blackfin
code. Decoding is checked against GNU objdump and semantics against the GNU
Blackfin simulator. It was built to reverse-engineer the ADSP-BF531 firmware of
the Pioneer CDJ-2000NXS.

## Install

1. Download `ghidra_<version>_PUBLIC_Blackfin.zip` from
   [Releases](https://github.com/geepot/ghidra-blackfin/releases), or
   [build it](#build).
2. In Ghidra: *File → Install Extensions*, **+**, pick the zip, restart Ghidra.

The zip is tied to the Ghidra version it was built against (the current release
targets 12.1.3); rebuild it for any other 12.x release. Programs analysed with an
earlier build keep the old instruction lengths in their listing: clear and
re-disassemble them after upgrading.

## Quick start

Ghidra selects **`Blackfin:LE:32:default`** (compiler spec `default`, "GNU
Blackfin") automatically for 32-bit little-endian Blackfin ELF files. For a raw
image or an LDR boot stream, choose that language when importing; for a raw
memory image, also set its load address. An LDR stream must first be unpacked
into its target memory regions.

## Features

- **All encodings GNU objdump decodes**, with objdump's assembly syntax
  (spacing and number format aside, the listing text equals objdump's).
  Offsets and immediates are shown scaled, as objdump shows them.
- **Semantics as the GNU simulator executes them**: data results and
  ASTAT flags (AZ, AN, AC0/AC1, V/VS, AV0/AV1, AQ, CC, the *_COPY bits) for
  ALU, shift, bit-field, divide-step, 16x16 multiply and multiply-accumulate
  in all ten modes (default, S2RND, T, W32, FU, TFU, IS, ISS2, IH, IU, with
  and without (M)), 40-bit accumulators with saturation, SEARCH, BITMUX,
  VIT_MAX, BXOR, EXPADJ, SIGNBITS, ONES, ALIGN, PACK, BYTEPACK/BYTEUNPACK.
- **Multi-issue packets** (`DSP32 || slot || slot`): the DSP operation runs
  first; both 16-bit slots read the registers as they were before the packet
  (a snapshot, the `*_P` registers), as the hardware does.
- **Zero-overhead hardware loops**: `LSETUP` marks the loop-bottom
  instruction in the context register; that instruction then decrements LC0
  or LC1 and branches back to the loop top, so loops decompile as loops.
- **Circular DAG addressing**: post-modified I0-I3 pointers wrap within the
  matching B/L buffer when L is nonzero; L=0 uses linear addressing.
- `CALL` sets RETS; `LINK`/`UNLINK` keep RETS above the saved FP; push/pop
  multiple use the hardware register order; `CLI`/`STI` move IMASK.

## Limitations

- **Opaque operations** (user operations with honest inputs and outputs): the
  byte-video operations `BYTEOP1P/2P/3P/16P/16M` and `SAA`, `DISALGNEXCPT`,
  cache control, `IDLE`, `RAISE`, `EXCPT` and the simulator pseudo instructions
  (`DBG`, `OUTC`, `HLT`, `DBGA`...).
- Circular DAG updates assume a configured buffer: the incoming I register lies
  within its B/L span and the modify amount does not exceed its length. Cases
  outside that setup have not been checked against hardware.

## Build

Needs a Ghidra 12.x install (for `support/sleigh`) and Python 3.

```sh
tools/build.sh             # dist/ghidra_<ver>_PUBLIC_Blackfin.zip
tools/build.sh --install   # ... and unpack it into that Ghidra version's per-user Extensions folder
```

Set `GHIDRA_INSTALL_DIR` if Ghidra is not Homebrew's `opt/ghidra`. The `.sla` is
compiled at build time and never committed; the zip is reproducible (fixed dates
and modes).

## Testing and verification

| Check | Result |
| --- | --- |
| Every 16-bit instruction word against objdump (`tools/bfin_isatest.py 16`) | 65,488 of 65,536 identical; 48 LSETUP offset text differences |
| 1.55 million sampled 32/64-bit encodings with random parallel slots (`tools/bfin_isatest.py 32 96`) | 1,547,421 match; 867 LSETUP offset text differences |
| Semantics against the GNU simulator (`tools/bfin_semtest.py`) | GUI bootstrap: 720 match; all 16-bit encodings: 59,914 match; sampled DSP packets: 20,121 match; no mismatches after documented oracle exclusions |
| Circular DAG addressing (`tools/bfin_dagtest.py`) | 13 nonzero-L and linear cases agree with the GNU simulator |
| Whole reconstructed GUI ELF against objdump (`tools/bfin_crosscheck.py`) | All 103,614 analysed instructions agree |
| GUI LDR image in adjacent research repository (`tools/bfin_gui_smoke.py IMAGE`) | Its two L1 code blocks sweep as 367 two-byte and 170 four-byte instructions (1,414 bytes); all 368 distinct encodings match objdump; reconstructed ELF selects Blackfin automatically |

The harnesses run Ghidra headless against the installed extension. The full
comparison needs an objdump with Blackfin support, plus `bfin-elf-as`/
`bfin-elf-ld` and the GNU Blackfin simulator for the semantic test. The
directed DAG, debug and GUI smoke tests only need Ghidra. [docs/verification.md](docs/verification.md)
has the setup, the order to run them in, the objdump LSETUP quirk and the
simulator cases left out of the comparison. No firmware or other third-party
image is committed.

## Contributing

Bug reports and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
For a wrong decode or wrong semantics, please use the
[issue template](https://github.com/geepot/ghidra-blackfin/issues/new?template=wrong-decode.md)
and include the address, the bytes, the objdump output and what you expected.

## Licence

GPL-3.0-or-later: the decoder and semantics follow GPL-3.0-or-later references
(binutils `bfin-dis.c`, gdb's `bfin-sim.c`) closely. See [NOTICE.md](NOTICE.md) and
[LICENSE.txt](LICENSE.txt). Ghidra itself is Apache-2.0; this is a separately
distributed extension.
