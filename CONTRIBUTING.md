# Contributing

Issues and pull requests are welcome.

## Reporting a wrong decode or wrong semantics

Use the [wrong decode / semantics](https://github.com/geepot/ghidra-blackfin/issues/new?template=wrong-decode.md)
issue template. The most useful report has:

- the Ghidra version and extension version (release or commit);
- the address and the raw instruction bytes (for a multi-issue packet, all
  8 bytes);
- what Ghidra shows (listing line, or p-code / decompiler output) and what you
  expected;
- the same bytes through GNU objdump, e.g.
  `objdump -D -b binary -m bfin --adjust-vma=<address> insn.bin`, and for a
  semantics problem, what the GNU simulator does if you can run it.

Only post bytes you are allowed to share; never attach whole firmware images.

## Changing the module

- GNU objdump is the decoding oracle and the GNU simulator the semantic
  oracle. A change to decoding or semantics should keep
  `tools/bfin_isatest.py 16` and `32` and `tools/bfin_semtest.py dsp` and
  `16` clean; say in the PR what you ran and what changed in the summary line.
  [docs/verification.md](docs/verification.md) explains the setup.
- If you disagree with an oracle (as with the two objdump quirks), document why
  in [docs/verification.md](docs/verification.md) with the hardware or manual
  reference.
- Keep `NOTICE.md` current when you consult a new reference, and do not commit
  firmware images or other third-party binaries.
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) under *Unreleased*.

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
