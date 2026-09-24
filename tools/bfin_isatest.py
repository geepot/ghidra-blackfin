#!/usr/bin/env python3
"""Compare the Blackfin SLEIGH decoder with GNU objdump over synthetic encodings.

    scripts/bfin_isatest.py 16      every 16-bit instruction word (65536 slots)
    scripts/bfin_isatest.py 32 [n]  every 32-bit first word x n (24) second words, random parallel slots
    scripts/bfin_isatest.py gui     every distinct instruction encoding objdump finds in the GUI image

Each encoding sits at the start of a 10-byte slot [w0 w1 s1 s2 NOP]; s1/s2 are always
16-bit words, so objdump cannot run across a slot boundary. Ghidra decodes every slot
with DisasmSlots.java (installed extension). Both texts are normalized (whitespace,
comments and number formats removed) and compared. Categories:
  match     same length and text
  missing   objdump decodes it, Ghidra does not
  extra     Ghidra decodes something objdump calls ILLEGAL
  length    both decode, different length
  text      same length, different text
Summary to stderr; build/isa/<mode>.diff.tsv lists every non-match.
"""
import os
import random
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bfin_crosscheck import norm, parse_objdump  # noqa: E402

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBJDUMP = "/opt/homebrew/opt/binutils/bin/objdump"
GHIDRA = os.environ.get("GHIDRA", "/opt/homebrew/opt/ghidra/libexec")
BASE = 0x1000
SLOT = 10


def is32(w):
    return (w & 0xC000) == 0xC000 and (w & 0xFF00) != 0xF800


def slot16(rng):
    """A random 16-bit word for a parallel slot: mostly load/store space, some NOP."""
    r = rng.random()
    if r < 0.3:
        return 0
    if r < 0.9:
        return rng.randrange(0x8000, 0xC000)
    while True:
        w = rng.randrange(0, 0x10000)
        if not is32(w):
            return w


def corpus(mode, samples=24):
    rng = random.Random(samples)
    words = []
    if mode == "16":
        for w0 in range(0x10000):
            words.append((w0, 0, 0, 0))
    elif mode == "32":
        firsts = [w for w in range(0xC000, 0x10000) if is32(w)]
        for w0 in firsts:
            seconds = [0, 0xFFFF] + [rng.randrange(0x10000) for _ in range(samples - 2)]
            for w1 in seconds:
                words.append((w0, w1, slot16(rng), slot16(rng)))
    elif mode == "gui":
        seen = set()
        blob = open(os.path.join(W, "inputs/gui-sdram-0x00c66e44.bin"), "rb").read()
        out = subprocess.run([OBJDUMP, "-D", "-z", "-b", "binary", "-m", "bfin", os.path.join(W, "inputs/gui-sdram-0x00c66e44.bin")],
                             capture_output=True, text=True, check=True).stdout
        base = 0
        for a, n, text in parse_objdump(out):
            if "ILLEGAL" in text:
                continue
            ws = struct.unpack_from("<%dH" % (n // 2), blob, a - base)
            key = tuple(ws) + (0,) * (4 - len(ws))
            if key not in seen:
                seen.add(key)
                words.append(key)
    else:
        raise SystemExit(__doc__)
    return words


def objdump(path):
    out = subprocess.run([OBJDUMP, "-D", "-z", "-b", "binary", "-m", "bfin", f"--adjust-vma={BASE:#x}", path],
                         capture_output=True, text=True, check=True).stdout
    return {a: (n, t) for a, n, t in parse_objdump(out) if (a - BASE) % SLOT == 0}


def ghidra(path, tsv):
    proj = os.path.join(W, "build/isa/proj")
    os.makedirs(proj, exist_ok=True)
    env = dict(os.environ, JAVA_HOME=os.environ.get(
        "JAVA_HOME", "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"))
    r = subprocess.run([f"{GHIDRA}/support/analyzeHeadless", proj, "isa", "-import", path, "-overwrite",
                        "-loader", "BinaryLoader", "-loader-baseAddr", hex(BASE),
                        "-processor", "Blackfin:LE:32:default", "-noanalysis",
                        "-scriptPath", os.path.join(W, "ghidra_scripts"),
                        "-postScript", "DisasmSlots.java", tsv, str(SLOT), "-deleteProject"],
                       capture_output=True, text=True, env=env)
    if r.returncode or not os.path.exists(tsv):
        sys.stderr.write(r.stdout[-4000:] + r.stderr[-4000:])
        raise SystemExit("ghidra failed")
    gh = {}
    for line in open(tsv):
        a, n, text = line.rstrip("\n").split("\t", 2)
        gh[int(a)] = (int(n), text)
    return gh


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    words = corpus(mode, int(sys.argv[2]) if len(sys.argv) > 2 else 24)
    d = os.path.join(W, "build/isa")
    os.makedirs(d, exist_ok=True)
    binpath = os.path.join(d, f"{mode}.bin")
    with open(binpath, "wb") as f:
        for ws in words:
            f.write(struct.pack("<5H", *ws, 0))
    od = objdump(binpath)
    gh = ghidra(binpath, os.path.join(d, f"{mode}.ghidra.tsv"))
    stats = Counter()
    shapes = defaultdict(Counter)
    with open(os.path.join(d, f"{mode}.diff.tsv"), "w") as out:
        for i, ws in enumerate(words):
            a = BASE + i * SLOT
            on, ot = od.get(a, (0, "?"))
            gn, gt = gh.get(a, (0, ""))
            illegal = "ILLEGAL" in ot
            if illegal and gn == 0:
                kind = "match"
            elif illegal:
                kind = "extra"
            elif gn == 0:
                kind = "missing"
            elif gn != on:
                kind = "length"
            elif norm(gt) != norm(ot):
                kind = "text"
            else:
                kind = "match"
            stats[kind] += 1
            if kind != "match":
                hexw = " ".join(f"{w:04x}" for w in ws[: max(on, gn, 2) // 2])
                out.write(f"{kind}\t{hexw}\t{ot}\t{gt}\n")
                shape = re.sub(r"\b([RPIMBL][0-7]|SP|FP|A[01])\b", "X", re.sub(r"0x[0-9a-f]+|-?\b\d+\b", "N", ot.split(";")[0]))
                shapes[kind][shape] += 1
    print(" ".join(f"{k}={v}" for k, v in stats.most_common()), file=sys.stderr)
    for kind, c in shapes.items():
        print(f"-- {kind}", file=sys.stderr)
        for s, n in c.most_common(12):
            print(f"{n:7d}  {s}", file=sys.stderr)


if __name__ == "__main__":
    assert norm("R0 = -0x3c (X);\t\t/* R0=0xffffffc4(-60) */") == "R0=-60(X)"
    assert norm("LSETUP(0x0xc6c9c4, 0x0xc6cb60) LC0 = P0 >> 0x1;") == norm("LSETUP ( 0x00c6c9c4 , 0x00c6cb60 ) LC0 = P0 >> 0x1")
    assert norm("[FP -0x4] = R0;") == "[FP-4]=R0"
    main()
