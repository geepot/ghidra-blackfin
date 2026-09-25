# ghidra-blackfin

A Ghidra 12 processor extension for the **classic Analog Devices Blackfin ISA**
(ADSP-BF53x and relatives): SLEIGH language `Blackfin:LE:32:default`. Ghidra has no
Blackfin support; this module decodes the whole instruction set, including multi-issue
packets and hardware loops, and gives every instruction p-code semantics, so the
decompiler works on Blackfin code.

Decoding is checked instruction by instruction against GNU objdump and the semantics
against the GNU Blackfin simulator (see [Verification](#verification)). It was built
to reverse-engineer the ADSP-BF531 firmware of a DJ player and has been exercised on
160,291 real instructions, all of which agree with objdump.

## Install

1. Download `ghidra_<version>_PUBLIC_Blackfin.zip` for your Ghidra version from
   [Releases](../../releases), or build it (below).
2. In Ghidra: *File → Install Extensions*, **+**, pick the zip, restart Ghidra.
3. Import a raw image (or an ELF) and choose language `Blackfin:LE:32:default`; for a raw
   image, set its load address.

The zip is tied to the Ghidra version it was built against; rebuild it for any
other 12.x release.

## Build

Needs a Ghidra 12.x install (for `support/sleigh`) and Python 3.

```sh
tools/build.sh             # dist/ghidra_<ver>_PUBLIC_Blackfin.zip
tools/build.sh --install   # ... and unpack it into your per-user Extensions folder
```

Set `GHIDRA_INSTALL_DIR` if Ghidra is not Homebrew's `opt/ghidra`. The `.sla` is
compiled at build time and never committed; the zip is reproducible (fixed dates and
modes). Programs analysed with an earlier build keep the old instruction lengths in
their listing: clear and re-disassemble them after upgrading.

## What it models

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
- `CALL` sets RETS; `LINK`/`UNLINK` keep RETS above the saved FP; push/pop
  multiple use the hardware register order; `CLI`/`STI` move IMASK.

Opaque (user operations with honest inputs and outputs): the byte-video
operations `BYTEOP1P/2P/3P/16P/16M` and `SAA`, `DISALGNEXCPT`, cache control,
`IDLE`, `RAISE`, `EXCPT` and the simulator pseudo instructions (`DBG`, `OUTC`,
`HLT`, `DBGA`...).

Not modelled: circular DAG addressing (L0-L3 non-zero). I registers are plain
pointers, as the GCC ABI keeps L0-L3 at zero.

## Verification

| Check | Command | Result |
| --- | --- | --- |
| Every 16-bit instruction word against objdump | `tools/bfin_isatest.py 16` | 65,448 of 65,536 identical; the rest are the objdump quirks below |
| 1.5M sampled 32/64-bit encodings with random parallel slots | `tools/bfin_isatest.py 32 96` | identical except the quirks below |
| Every encoding in a real code image | `tools/bfin_isatest.py image IMAGE` | identical except the quirks below |
| Semantics against the GNU simulator: random register states, a memory window per case | `tools/bfin_semtest.py [image\|dsp\|16]` | 62,700 + 59,914 + 18,764 cases, no mismatch |
| A whole analysed program against objdump, per code run | `ExportInstructions.java`, then `tools/bfin_crosscheck.py` | 160,291 of 160,291 instructions agree |

The harnesses run Ghidra headless with the *installed* extension (`GHIDRA`, default
Homebrew's `opt/ghidra/libexec`; JDK 21 via `JAVA_HOME`) and need:

| Variable | Tool | Default |
| --- | --- | --- |
| `BFIN_OBJDUMP` | an objdump with Blackfin support (binutils `--enable-targets=all`, or `bfin-elf-objdump`) | Homebrew binutils' `objdump` |
| `BFIN_BINUTILS` | directory with `bfin-elf-as` and `bfin-elf-ld` (semantic test) | `/usr/local/bin` |
| `BFIN_RUN` | the GNU Blackfin simulator (gdb's sim, `--target=bfin-elf`) | `bfin-elf-run` |

Outputs go to `build/isa/` and `build/sem/`. No firmware or other third-party image
is committed; `image` mode reads whatever image you pass.

Known differences, both on the oracle side:

- objdump sign-extends LSETUP start/end offsets; they are unsigned
  (pcrel5m2, lppcrel11m2), as the simulator and the hardware treat them.
- objdump prints `DBG`/`PRNT`/`DBGAL`/`DBGAH` with reserved register numbers
  as "Illegal register"; those do not decode here.

Simulator cases left out of the comparison: encodings it rejects (it is
stricter than objdump), host-undefined results (register shifts by negative
counts), its out-of-bounds write for a 32-bit MAC1 result with dst=7, packets
that write one register twice, and an uninitialised flag in
`Rd = A1 + A0, Rd = A1 - A0`. Packet writeback of data registers needs the
simulator's `BFIN_PARALLEL_WRITEBACK=1` switch, which the test sets.

## Source layout

The language, in `data/languages/`:

| File | Content |
| --- | --- |
| `blackfin.slaspec` | registers, context, tokens, register attachments |
| `bfin_macros.sinc` | ASTAT flag helpers |
| `bfin_16.sinc` | 16-bit instructions; the parallel-capable ones in `S16` |
| `bfin_32.sinc` | LSETUP, immediate loads, long jump/call, 16-bit-offset loads/stores, LINK |
| `bfin_dsp.sinc` | dsp32mac, dsp32mult |
| `bfin_dspalu.sinc` | dsp32alu |
| `bfin_dspshift.sinc` | dsp32shift, dsp32shiftimm |
| `bfin_par.sinc` | multi-issue packets |
| `bfin_loop.sinc` | root table and hardware-loop back-edges |

Test tooling: `tools/` (harnesses and `build.sh`) and `ghidra_scripts/`
(`DisasmSlots.java` decodes the synthetic slots, `BfinEmuTest.java` runs cases in
Ghidra's p-code emulator, `ExportInstructions.java` dumps a program's instructions).

## Contributing

Issues and pull requests are welcome.

- GNU objdump is the decoding oracle and the GNU simulator the semantic oracle. A
  change to decoding or semantics should keep `tools/bfin_isatest.py 16` and
  `32` and `tools/bfin_semtest.py dsp` and `16` clean; say in the PR what you ran and
  what changed in the summary line.
- If you disagree with an oracle (as with the two objdump quirks above), document why
  in the README with the hardware or manual reference.
- Keep `NOTICE.md` current when you consult a new reference, and do not commit
  firmware images or other third-party binaries.

## Licence

GPL-3.0-or-later: the decoder and semantics follow GPL-3.0-or-later references
(binutils `bfin-dis.c`, gdb's `bfin-sim.c`) closely. See [NOTICE.md](NOTICE.md) and
[LICENSE.txt](LICENSE.txt). Ghidra itself is Apache-2.0; this is a separately
distributed extension.
