# Source provenance and licensing

This is an independent Ghidra SLEIGH port informed by the instruction masks,
field layouts, and register maps in `0bs3n/arch-blackfin`, commit
`5cd19a58b7790ab18dc5100ef8033254945329af` (2022-05-27):

<https://github.com/0bs3n/arch-blackfin>

The upstream repository's top-level `LICENSE` is MIT and attributes copyright
to 0bs3n (2022). Its `disassembler/include/bfin.h`, however, carries an
explicit GPLv2-or-later notice and says it is based partly on GNU libopcodes.
Because the encoding tables in this port were checked against that file, this
module is conservatively distributed as GPL-2.0-or-later. Do not describe the
upstream disassembler, taken as a whole, as unambiguously MIT-only.

The instruction syntax and execution behavior were also checked against the
GNU binutils Blackfin disassembler shipped by Homebrew. GNU binutils is GPLv3+
and is used only as an external reference implementation/test oracle; no
binutils source is vendored here.

The current SLEIGH implementation specifically consulted upstream field maps
and behavior for program control, register moves, immediate-half loads,
hardware-loop setup, DAG and pointer load/store classes, push/pop classes,
condition-code moves, logic/bit operations, and DSP32 multi-issue packet
framing. The implementation is independently expressed in SLEIGH; the pinned
commit above remains the provenance point for those encodings.

Ghidra is an Apache-2.0 project. This directory is a separately distributed
processor extension and is not part of Ghidra itself.
