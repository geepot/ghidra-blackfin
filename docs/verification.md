# Verification

Decoding is checked instruction by instruction against GNU objdump, and the
p-code semantics against the GNU Blackfin simulator. The harnesses live in
`tools/` and `ghidra_scripts/`; none of them needs a committed image.

## Results

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

## Running the harnesses

1. Build and install the extension (`tools/build.sh --install`); the harnesses
   drive the *installed* copy, not `build/`.
2. `python3 tools/bfin_isatest.py 16` (and `32 [n]`, or `image IMAGE`). It
   prints a summary to stderr and writes every non-match to
   `build/isa/<mode>.diff.tsv`. For `16`, the expected result is 65,448
   `match`, 48 `text` (the LSETUP offset quirk) and 40 `missing` (the
   `DBG`/`PRNT`/`DBGAL`/`DBGAH` illegal-register quirk).
3. `python3 tools/bfin_semtest.py [image|dsp|16|all] [limit]` reuses the
   `build/isa/` images from step 2 and writes mismatches to `build/sem/diff.tsv`.
4. For a whole analysed program: run `ghidra_scripts/ExportInstructions.java`,
   then `tools/bfin_crosscheck.py program.ghidra.tsv IMAGE BASE [IMAGE BASE ...]`.

`tools/build.sh` deletes `build/`, including earlier harness output.
