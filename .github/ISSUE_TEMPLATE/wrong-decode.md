---
name: Wrong decode or semantics
about: An instruction disassembles, lifts or decompiles incorrectly
title: "Wrong decode/semantics: <instruction> at <address>"
---

**Versions**
- Ghidra:
- Extension (release or commit):

**Location**
- Address:
- Raw bytes, in file byte order (all 8 bytes for a multi-issue packet):

```
```

**What Ghidra shows** (listing line, and p-code or decompiler output if the
problem is semantics):

```
```

**What you expected**, and why (manual reference, hardware behaviour):

**Oracle output**, if available:
- `objdump -D -b binary -m bfin --adjust-vma=<address> insn.bin`
- GNU Blackfin simulator (`bfin-elf-run`) register state, for semantics

```
```

Please post only bytes you are allowed to share.
