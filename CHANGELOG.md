# Changelog

## Unreleased

### Documentation
* The README is now a short overview (install, quick start, features,
  limitations, build, testing). Harness setup, the objdump quirks and the
  simulator exclusions moved to `docs/verification.md`; the source layout
  moved to `CONTRIBUTING.md`.
* Added `CONTRIBUTING.md`, this changelog and a "wrong decode or semantics"
  issue template.
* Added an ELF opinion for 32-bit little-endian Blackfin files. Raw images
  still need the language and load address chosen when importing.

### Processor
* Model circular I-register post-modification for configured B/L buffers,
  including negative M-register steps and the L=0 linear case.
* Decode the 40 reserved-register simulator debug forms with objdump's
  literal operand text.
* Added directed Ghidra emulator checks and a smoke test for the stock GUI
  image's L1 bootstrap.

## 1.0.0 - 2026-09-25

First public release, built for Ghidra 12.1.3.

* `Blackfin:LE:32:default` SLEIGH language for the classic Blackfin ISA
  (ADSP-BF53x), decoding every encoding GNU objdump decodes (bar two documented objdump
  quirks), in objdump's syntax.
* P-code semantics following the GNU simulator, including ASTAT flags,
  40-bit accumulators, all multiply/MAC modes, multi-issue packets and
  zero-overhead hardware loops.
* `tools/build.sh` for a reproducible extension zip, and the objdump and
  simulator harnesses (`tools/bfin_isatest.py`, `tools/bfin_semtest.py`,
  `tools/bfin_crosscheck.py`).
