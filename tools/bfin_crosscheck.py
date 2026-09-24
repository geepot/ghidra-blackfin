#!/usr/bin/env python3
"""Cross-check Ghidra's Blackfin disassembly against GNU objdump.

    scripts/bfin_crosscheck.py build/gui-sdram.ghidra.tsv inputs/gui-sdram-0x00c66e44.bin 0x00c66e44 > build/gui-crosscheck.tsv

The TSV comes from ExportInstructions.java. objdump runs once per contiguous run of
Ghidra instructions, so both tools start every run at the same address. Each Ghidra
instruction is classified:
  agree       same address and length, both decode it
  undecoded   Ghidra shows a raw placeholder (BFIN16/DSP32/...) that objdump decodes
  illegal     objdump reports ILLEGAL where Ghidra decoded an instruction
  length      objdump's instruction at this address has a different length
  desync      objdump has no instruction starting at this address
A summary goes to stderr; every non-agreeing row goes to stdout.
"""
import re
import subprocess
import sys
from collections import Counter

OBJDUMP = "/opt/homebrew/opt/binutils/bin/objdump"
LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$")
PLACEHOLDER = re.compile(r"^(BFIN16|BFIN32|DSP32|UNDEF|\?\?|bad)", re.I)


def runs(rows):
    start = prev_end = None
    for addr, length, *_ in rows:
        if start is None or addr != prev_end:
            if start is not None:
                yield start, prev_end
            start = addr
        prev_end = addr + length
    if start is not None:
        yield start, prev_end


def objdump(binary, base, lo, hi):
    out = subprocess.run([OBJDUMP, "-D", "-b", "binary", "-m", "bfin", f"--adjust-vma={base:#x}",
                          f"--start-address={lo:#x}", f"--stop-address={hi:#x}", binary],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            yield int(m.group(1), 16), len(m.group(2).split()), m.group(3).strip()


def main():
    tsv, binary, base = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
    rows = []
    for line in open(tsv):
        a, n, text, fn = line.rstrip("\n").split("\t")
        rows.append((int(a), int(n), text, fn))
    rows.sort()
    od = {}
    for lo, hi in runs(rows):
        for a, n, text in objdump(binary, base, lo, hi):
            od[a] = (n, text)
    stats = Counter()
    for a, n, text, fn in rows:
        o = od.get(a)
        if o is None:
            kind = "desync"
        elif o[1].startswith("ILLEGAL"):
            kind = "illegal"
        elif o[0] != n:
            kind = "length"
        elif PLACEHOLDER.match(text):
            kind = "undecoded"
        else:
            kind = "agree"
        stats[kind] += 1
        if kind != "agree":
            fn_s = f"{int(fn):#010x}" if fn else ""
            print(f"{kind}\t{a:#010x}\t{n}\t{text}\t{o[1] if o else ''}\t{fn_s}")
    print(" ".join(f"{k}={v}" for k, v in stats.most_common()), file=sys.stderr)


if __name__ == "__main__":
    assert list(runs([(0, 2, "", ""), (2, 4, "", ""), (8, 2, "", "")])) == [(0, 6), (8, 10)]
    main()
