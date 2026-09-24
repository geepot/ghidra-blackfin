# Blackfin processor module for Ghidra

SLEIGH language `Blackfin:LE:32:default` for the classic Analog Devices
Blackfin ISA (ADSP-BF53x), as used by the CDJ-2000NXS GUI processor
(ADSP-BF531). It decodes the whole instruction set, including multi-issue
packets, and gives every instruction p-code semantics.

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

Run from the workspace (`~/Ghidra/cdj2000nxs`) after `scripts/setup.sh extension`:

| Check | Script | Result |
| --- | --- | --- |
| Every 16-bit word, 1.5M sampled 32/64-bit encodings with random parallel slots, every encoding in the GUI image, against `objdump` | `scripts/bfin_isatest.py 16`, `32 96`, `gui` | identical except the two objdump quirks below |
| Semantics against the GNU simulator (`run`, operating environment), random register states, a memory window per case | `scripts/bfin_semtest.py gui`, `16`, `dsp` | 62,700 + 59,914 + 18,764 cases, no mismatch |
| Re-disassembled GUI program against `objdump`, per code run | `scripts/bfin_crosscheck.py` | 160,291 of 160,291 instructions agree |

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

## Build and install

```sh
scripts/setup.sh extension
```

compiles `data/languages/blackfin.slaspec` with Ghidra's `support/sleigh`,
writes a reproducible `build/ghidra_<ver>_PUBLIC_Blackfin.zip` and unpacks it
into the user's Ghidra Extensions folder. Restart Ghidra afterwards. Programs
analysed with an earlier build keep the old instruction lengths in their
listing; re-decode them with `scripts/setup.sh redisassemble` (Ghidra closed).

## Source layout

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

Provenance and licence: [NOTICE.md](NOTICE.md).
