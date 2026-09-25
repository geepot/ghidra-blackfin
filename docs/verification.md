# Verification

Decoding is checked instruction by instruction against GNU objdump, and the
p-code semantics against the GNU Blackfin simulator. The harnesses live in
`tools/` and `ghidra_scripts/`; none of them needs a committed image.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Every 16-bit instruction word against objdump | `tools/bfin_isatest.py 16` | 65,488 of 65,536 identical; 48 LSETUP offset text differences |
| 1.55 million sampled 32/64-bit encodings with random parallel slots | `tools/bfin_isatest.py 32 96` | 1,547,421 match; 867 LSETUP offset text differences |
| Every distinct encoding in the stock GUI L1 bootstrap | `tools/bfin_isatest.py image build/gui/l1.bin` | 368 match |
| Semantics against the GNU simulator: random register states, a memory window per case | `tools/bfin_semtest.py [image\|dsp\|16]` | GUI: 720 match, 3 simulator-undefined; 16-bit: 59,914 match, 252 undefined; DSP: 20,121 match, 597 undefined, 23,570 rejected; no mismatch |
| Directed circular DAG cases against the GNU simulator | `tools/bfin_dagtest.py` | 13 agree, including nonzero L registers |
| Whole reconstructed GUI ELF against objdump, per code run | `ExportInstructions.java`, then `tools/bfin_crosscheck.py` | All 103,614 analysed instructions agree |

The harnesses run Ghidra headless with the *installed* extension (`GHIDRA`, default
Homebrew's `opt/ghidra/libexec`; JDK 21 via `JAVA_HOME`) and need:

| Variable | Tool | Default |
| --- | --- | --- |
| `BFIN_OBJDUMP` | an objdump with Blackfin support (binutils `--enable-targets=all`, or `bfin-elf-objdump`) | Homebrew binutils' `objdump` |
| `BFIN_BINUTILS` | directory with `bfin-elf-as` and `bfin-elf-ld` (semantic test) | directory of `bfin-elf-as` on `PATH` |
| `BFIN_RUN` | the GNU Blackfin simulator (gdb's sim, `--target=bfin-elf`) | `bfin-elf-run` |

For the complete local run, [GNU binutils 2.44](https://sourceware.org/pub/binutils/releases/binutils-2.44.tar.xz)
(`bfin-elf-as` and `bfin-elf-ld`) and
[GDB simulator 17.2](https://sourceware.org/pub/gdb/releases/gdb-17.2.tar.xz)
(`bfin-elf-run`) were built from the official Sourceware release archives and
placed in `../bfin-elf-toolchain/prefix/bin/`, outside this repository. The
archives are in `../bfin-elf-toolchain/downloads/`, and their SHA-512 hashes
were checked against Sourceware's published `sha512.sum` files. Set
`BFIN_BINUTILS` to the absolute path of `../bfin-elf-toolchain/prefix/bin` and
`BFIN_RUN` to its `bfin-elf-run`.

On macOS, use GNU `sed` ahead of `/usr/bin/sed` while building GDB's simulator;
the bundled module generator otherwise emits an empty `bfin/modules.c` and the
simulator crashes at startup. With Xcode Clang 21, compile
`sim/bfin/bfin-sim.o` using `CFLAGS='-O0 -g'` before `install-sim`: at `-O2`,
the simulator left the 16-bit immediate instruction family unchanged. The
semantic harness zeros its checksum registers with half-register moves because
those short immediate forms would make its results depend on that simulator
build issue.

Outputs go to `build/isa/` and `build/sem/`. No firmware or other third-party image
is committed; `image` mode reads whatever image you pass.

Known difference on the oracle side:

- objdump sign-extends LSETUP start/end offsets; they are unsigned
  (pcrel5m2, lppcrel11m2), as the simulator and the hardware treat them.

The 40 reserved-register `DBG`/`PRNT`/`DBGAL`/`DBGAH` forms now decode with
objdump's literal "Illegal register" operand. `tools/bfin_debugtest.py` checks
all 40 without requiring objdump.

Simulator cases left out of the comparison: encodings it rejects (it is
stricter than objdump), host-undefined results (register shifts by negative
counts), its out-of-bounds write for a 32-bit MAC1 result with dst=7, packets
that write one register twice, packet reads after another slot wrote the same
register (GDB 17.2 does not preserve the prepacket value), and an uninitialised
flag in `Rd = A1 + A0, Rd = A1 - A0`.

## Running the harnesses

1. Build and install the extension (`tools/build.sh --install`); the harnesses
   drive the *installed* copy, not `build/`.
2. `python3 tools/bfin_isatest.py 16` (and `32 [n]`, or `image IMAGE`). It
   prints a summary to stderr and writes every non-match to
   `build/isa/<mode>.diff.tsv`. For `16`, the result is 65,488 `match` and
   48 `text` (the LSETUP offset quirk). Every decoded slot must also build
   p-code: a slot whose constructor matches but whose p-code fails (for example
   an attach-table index with no register) is reported as `pcode` and the run
   exits non-zero; there are none in `16` or `32 96`.
3. `python3 tools/bfin_semtest.py [image|dsp|16|all] [limit]` reuses the
   `build/isa/` images from step 2 and writes mismatches to `build/sem/diff.tsv`.
   `python3 tools/bfin_dagtest.py` exercises nonzero circular lengths in the
   Ghidra emulator and compares them with the GNU simulator when it is installed.
4. For a whole analysed program: run `ghidra_scripts/ExportInstructions.java`,
   then `tools/bfin_crosscheck.py program.ghidra.tsv IMAGE BASE [IMAGE BASE ...]`.
5. `python3 tools/bfin_gui_smoke.py ../cdj2000nxs-research/extracted/gui.image.bin`
   unpacks the two L1 code blocks from the stock LDR stream, imports their
   1,414 bytes at `0xffa08000`, and runs `ghidra_scripts/LinearSweep.java`.
   It checks 367 two-byte and 170 four-byte instructions. A reconstructed
   `gui-boot-memory.elf` also selects Blackfin without `-processor` and yields
   the same L1 length counts. Run `python3 tools/bfin_isatest.py image build/gui/l1.bin`
   after the smoke test to compare its 368 distinct instruction encodings with
   objdump; all 368 match.

`tools/build.sh` deletes `build/`, including earlier harness output.
