#!/usr/bin/env python3
"""Cross-check Ghidra's Blackfin disassembly against GNU objdump.

    tools/bfin_crosscheck.py program.ghidra.tsv IMAGE BASE [IMAGE BASE ...] > crosscheck.tsv

The TSV comes from ExportInstructions.java. objdump runs once per contiguous run of
Ghidra instructions, so both tools start every run at the same address. Each Ghidra
instruction is classified:
  agree       same address and length, both decode it
  undecoded   Ghidra shows a raw placeholder (BFIN16/DSP32/...) that objdump decodes
  illegal     objdump reports ILLEGAL where Ghidra decoded an instruction
  length      objdump's instruction at this address has a different length
  text        same length, but the operands or operation differ (normalized text)
  desync      objdump has no instruction starting at this address
A summary goes to stderr; every non-agreeing row goes to stdout.
"""
import os
import re
import subprocess
import sys
from collections import Counter

# an objdump built with Blackfin support (GNU binutils --enable-targets=all, or bfin-elf-objdump)
OBJDUMP = os.environ.get("BFIN_OBJDUMP", "/opt/homebrew/opt/binutils/bin/objdump")
LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(?:\t(.*))?$")
NUM = re.compile(r"(?<![A-Z0-9_.])(-?)(0X[0-9A-F]+|[0-9]+)")
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
    out = subprocess.run([OBJDUMP, "-D", "-z", "-b", "binary", "-m", "bfin", f"--adjust-vma={base:#x}",
                          f"--start-address={lo:#x}", f"--stop-address={hi:#x}", binary],
                         capture_output=True, text=True, check=True).stdout
    yield from parse_objdump(out)


def parse_objdump(out):
    """(address, length, text) per instruction; objdump wraps 8-byte packets onto a
    continuation line that carries bytes but no text."""
    cur = None
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        n = len(m.group(2).split())
        if m.group(3) is None and cur:
            cur[1] += n
            continue
        if cur:
            yield tuple(cur)
        cur = [int(m.group(1), 16), n, m.group(3).strip()]
    if cur:
        yield tuple(cur)


def norm(t):
    """Canonical instruction text: no comments, whitespace or number formatting."""
    t = re.sub(r"/\*.*?\*/", "", t)
    t = t.split(";")[0]
    t = re.sub(r"<[^>]*>", "", t).replace("0x0x", "0x").upper()
    t = NUM.sub(lambda m: str(int(m.group(1) + m.group(2), 0)), t)
    return re.sub(r"\s+", "", t)


def main():
    tsv = sys.argv[1]
    images = []
    for binary, base in zip(sys.argv[2::2], sys.argv[3::2]):
        base = int(base, 0)
        size = len(open(binary, "rb").read())
        images.append((base, base + size, binary))
    rows = []
    for line in open(tsv):
        a, n, text, fn = line.rstrip("\n").split("\t")
        rows.append((int(a), int(n), text, fn))
    rows.sort()
    od = {}
    checked = set()
    for lo, hi in runs(rows):
        img = next((i for i in images if i[0] <= lo < i[1]), None)
        if img is None:
            continue
        checked.add(lo)
        for a, n, text in objdump(img[2], img[0], lo, min(hi, img[1])):
            od[a] = (n, text)
    inside = lambda a: any(i[0] <= a < i[1] for i in images)
    stats = Counter()
    for a, n, text, fn in rows:
        o = od.get(a)
        if not inside(a):
            stats["unchecked"] += 1
            continue
        if o is None:
            kind = "desync"
        elif o[1].startswith("ILLEGAL"):
            kind = "illegal"
        elif o[0] != n:
            kind = "length"
        elif PLACEHOLDER.match(text):
            kind = "undecoded"
        elif norm(text) != norm(o[1]):
            kind = "text"
        else:
            kind = "agree"
        stats[kind] += 1
        if kind != "agree":
            fn_s = f"{int(fn):#010x}" if fn else ""
            print(f"{kind}\t{a:#010x}\t{n}\t{text}\t{o[1] if o else ''}\t{fn_s}")
    print(" ".join(f"{k}={v}" for k, v in stats.most_common()), file=sys.stderr)


if __name__ == "__main__":
    assert list(parse_objdump("  10:\t11 c9 85 c7 \tA || B || C;\n  14:\tc8 b2 e4 b2 \n  18:\t00 00       \tNOP;")) == [
        (0x10, 8, "A || B || C;"), (0x18, 2, "NOP;")]
    assert list(runs([(0, 2, "", ""), (2, 4, "", ""), (8, 2, "", "")])) == [(0, 6), (8, 10)]
    main()
