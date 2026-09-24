# Experimental Blackfin processor module for Ghidra

This directory contains a free, open-source Ghidra 11.4.2 processor
extension for the classic Analog Devices Blackfin ISA used by the
CDJ-2000NXS GUI processor (ADSP-BF531).

It is usable today for instruction alignment, direct and indirect branch/call
recovery, stack-frame recognition, full architectural register moves and
immediate construction, hardware-loop setup, common condition-code operations,
DAG/pointer memory traffic, three-register data/pointer arithmetic,
byte/halfword post-modify loads and stores, signed-offset loads/stores, and the
memory slots of common compiler-generated multi-issue packets.

This is still an experimental, corpus-driven port, not a complete Blackfin ISA
implementation. Unsupported 16-bit classes decode as `BFIN16`, unsupported
32-bit DSP primaries as `DSP32`, and unsupported 32-bit non-DSP encodings as
`BFIN32`. `DSP32_MULTI` consumes the full eight-byte packet and lifts supported
parallel memory slots, but its DSP32 primary operation is still opaque. A
`PAR16A` or `PAR16B` operand means that parallel slot also has no semantics.
These placeholders provide the correct length in the measured CDJ firmware
corpora described below; synchronization for unmeasured ISA encodings is not
claimed.

Remaining high-impact gaps include DSP32 arithmetic/shift semantics (including
the primary operation in every multi-issue packet), ALU dynamic-shift/divide
variants, complete halfword LDSTpmod pointer-update behavior, individual
register effects for range push/pop sets other than the `R7:4/P5:3` ABI set,
hardware-loop back-edge modeling, and specialized DSP/VLIW combinations.

## Measured corpus coverage

`BlackfinCorpusTest.java` linearly decodes two code corpora and keeps length and
representative instruction regressions reproducible. GNU binutils Blackfin
objdump is the instruction oracle.

| Corpus | Instructions | `BFIN16` | `DSP32` | Multi-issue packets |
| --- | ---: | ---: | ---: | ---: |
| L1 bootstrap `0xffa08000-0xffa08585` | 537 | 4 (0.74%) | 8 (1.49%) | 0 |
| Dense application-code subset `0x00d00000-0x00d3ffff` | 102,247 | 660 (0.65%) | 1,084 (1.06%) | 933 |

The application subset is a defensible executable corpus rather than every
initialized byte: it excludes later sparse and zero-filled material (the
`0x00d50000-0x00d5ffff` slice, for example, has no GNU-decoded instructions).
Of its 933 multi-issue packets, 330 still contain at
least one `PAR16` slot; all 933 still have an opaque DSP32 primary. GNU decoding
of both measured corpora agrees with the module's two-, four-, and eight-byte
instruction boundaries. That is a corpus-bounded synchronization result, not
a full-ISA proof.

Before the register/DAG/loop expansion, the L1 corpus had 157 `BFIN16` and 58
`DSP32` fallbacks. It now has 4 and 8 respectively, with the same 537
instructions consuming the same 1,414 bytes.

## Provenance and license

See [NOTICE.md](NOTICE.md). In short, the masks and field layouts were checked
against `0bs3n/arch-blackfin` commit
`5cd19a58b7790ab18dc5100ef8033254945329af`. Because a material upstream
opcode header is GPLv2-or-later despite the repository's top-level MIT file,
this extension is conservatively GPL-2.0-or-later.

## Compile the SLEIGH language

For the Homebrew Ghidra 11.4.2 installation used by this project:

```sh
GHIDRA_INSTALL_DIR=/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
_JAVA_OPTIONS=-Duser.home=/private/tmp/cdj-ghidra-home \
  PATH=/opt/homebrew/opt/openjdk@21/bin:/usr/bin:/bin \
  "$GHIDRA_INSTALL_DIR/support/sleigh" data/languages/blackfin.slaspec
```

The compiler writes `data/languages/blackfin.sla`. The `.sla` file is a build
artifact and should be regenerated rather than reviewed as source.

## Build and install the extension

```sh
GHIDRA_INSTALL_DIR=/opt/homebrew/Caskroom/ghidra/11.4.2-20250826/ghidra_11.4.2_PUBLIC
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
GRADLE_USER_HOME=/private/tmp/cdj-gradle-home \
  "$GHIDRA_INSTALL_DIR/support/gradle/gradlew" \
  -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" buildExtension
```

Install the generated `dist/ghidra_11.4.2_PUBLIC_*_Blackfin.zip` through
Ghidra's **File > Install Extensions** dialog, restart Ghidra, and choose
`Blackfin:LE:32:default` when importing a materialized GUI memory region.
For `reports/generated/gui-memory/0x00c66e44-0x00fd5557.bin`, set the raw
binary base address to `0x00c66e44`.

## Smoke test

After installing the extension, import that materialized runtime region at
base `0x00c66e44`, then run `BlackfinSmokeTest.java`. The script disassembles
the beginning of the GUI update bank selector at `0x00d09a34` and checks
direct forward and backward calls, `LINK`, split immediate loads, byte loads,
condition-code comparisons, conditional/unconditional branches, stack
push/pop, and `RTS`. It also asserts that both calls have direct flow targets
in Ghidra. The script prints `BLACKFIN_SMOKE_OK` on success.

The test can also be run headlessly after installing the extension:

```sh
mkdir -p /private/tmp/cdj-ghidra-project
_JAVA_OPTIONS=-Duser.home=/private/tmp/cdj-ghidra-home \
  PATH=/opt/homebrew/opt/openjdk@21/bin:/usr/bin:/bin \
  "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  /private/tmp/cdj-ghidra-project blackfin-smoke \
  -import ../../reports/generated/gui-memory/0x00c66e44-0x00fd5557.bin \
  -loader BinaryLoader -loader-baseAddr 0x00c66e44 \
  -processor Blackfin:LE:32:default -cspec default -noanalysis \
  -scriptPath ghidra_scripts -postScript BlackfinSmokeTest.java -overwrite
```

Run the corpus regressions with fresh project names (headless Ghidra projects
are persistent):

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  /private/tmp/cdj-ghidra-project blackfin-l1-corpus \
  -import ../../reports/generated/gui-memory/0xffa08000-0xffa08585.bin \
  -loader BinaryLoader -loader-baseAddr 0xffa08000 \
  -processor Blackfin:LE:32:default -cspec default -noanalysis \
  -scriptPath ghidra_scripts -postScript BlackfinCorpusTest.java l1 -overwrite

"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
  /private/tmp/cdj-ghidra-project blackfin-packet-corpus \
  -import ../../reports/generated/gui-memory/0x00c66e44-0x00fd5557.bin \
  -loader BinaryLoader -loader-baseAddr 0x00c66e44 \
  -processor Blackfin:LE:32:default -cspec default -noanalysis \
  -scriptPath ghidra_scripts -postScript BlackfinCorpusTest.java packet -overwrite
```

Use `BlackfinCorpusTest.java app` with the application import to reproduce the
`0x00d00000-0x00d3ffff` coverage row. Use `coverage` with the L1 import to print
each remaining fallback byte sequence.

GNU binutils remains the reference oracle while the port is incomplete:

```sh
/opt/homebrew/opt/binutils/bin/objdump -D -b binary -m bfin \
  --adjust-vma=0x00c66e44 \
  --start-address=0x00d09a34 --stop-address=0x00d09a82 \
  ../../reports/generated/gui-memory/0x00c66e44-0x00fd5557.bin
```

## Comparison with the existing `sualk` extension

[`sualk/ghidra-blackfin`](https://github.com/sualk/ghidra-blackfin) is a more
complete classic-Blackfin disassembler and successfully decodes the measured
CDJ corpora. See the project-wide
[GUI/Blackfin notes](../../docs/firmware/gui/gui-blackfin.md#existing-sualkghidra-blackfin-comparison)
for exact coverage, packet-representation, loader, and p-code findings.

It has no repository-level license declaration, and its SLEIGH files contain
no license header. Do not copy its decoder into this GPL-2.0-or-later module
unless the upstream author provides a compatible explicit license. Keeping
this implementation independent preserves a redistributable option with
CDJ-specific corpus regressions.
