# Source provenance and licensing

This is an independent Ghidra SLEIGH implementation of the classic Blackfin
ISA. No third-party source is vendored; the references below were read to get
encodings, syntax and behaviour right.

- **GNU binutils 2.44, `opcodes/bfin-dis.c`** (GPL-3.0-or-later): instruction
  classes, field layouts, the decode conditions of every class and the
  assembly syntax. GNU objdump built from it is the decoding oracle.
- **GNU gdb/sim 17.2, `sim/bfin/bfin-sim.c`** (GPL-3.0-or-later): execution
  semantics, including ASTAT flag updates, saturation and rounding. The
  simulator is the semantic oracle.
- **`0bs3n/arch-blackfin`**, commit `5cd19a58b7790ab18dc5100ef8033254945329af`,
  `disassembler/include/bfin.h` (GPL-2.0-or-later): field masks consulted by
  the first version of this module.

The decoder and semantics follow those GPL-3.0-or-later references closely, so
the module is distributed under **GPL-3.0-or-later** (the earlier
GPL-2.0-or-later terms allow this). See [LICENSE.txt](LICENSE.txt).

Ghidra is an Apache-2.0 project. This directory is a separately distributed
processor extension and is not part of Ghidra itself.
