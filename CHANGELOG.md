# Changelog

## Unreleased

### Documentation
* The README is now a short overview (install, quick start, features,
  limitations, build, testing). Harness setup, the objdump quirks and the
  simulator exclusions moved to `docs/verification.md`; the source layout
  moved to `CONTRIBUTING.md`.
* Added `CONTRIBUTING.md`, this changelog and a "wrong decode or semantics"
  issue template.
* Documented that there is no ELF loader opinion: choose
  `Blackfin:LE:32:default` by hand.

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
