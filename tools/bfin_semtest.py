#!/usr/bin/env python3
"""Differential test of the Blackfin p-code semantics against the GNU simulator.

    tools/bfin_semtest.py [image|dsp|16|all] [limit]

Needs build/isa/{image,32,16}.{bin,ghidra.tsv} from bfin_isatest.py (image: only if you ran it). Every decodable,
non-control-flow instruction encoding found in a code image (image), a sample of
synthetic DSP32 encodings (dsp), every 16-bit encoding (16) or all three runs once
per random register state
in Ghidra's p-code emulator (BfinEmuTest.java) and in the GNU Blackfin simulator
(`bfin-elf-run`, test programs built with bfin-elf-as). Each case owns a 256-byte memory
window that all its pointer registers (adjusted for immediate offsets) point into.
Compared: R0-R7, P0-P5, SP, FP, I/M/B/L, RETS, A0, A1, ASTAT and a sum/xor
checksum of the window. The simulator runs in its operating environment with an
exception handler that skips a case it rejects; those are counted, not compared.
Summary to stderr; build/sem/diff.tsv lists every mismatch.
"""
import os
import random
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict

W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
B = os.path.join(W, "build/sem")
GHIDRA = os.environ.get("GHIDRA", "/opt/homebrew/opt/ghidra/libexec")
# directory holding bfin-elf-as and bfin-elf-ld (GNU binutils configured --target=bfin-elf)
TOOLS = os.environ.get("BFIN_BINUTILS", "/usr/local/bin")
# the GNU Blackfin simulator (gdb sim, configured --target=bfin-elf)
SIM = os.environ.get("BFIN_RUN", "bfin-elf-run")
REGION = 0x01000000          # case i's window is REGION + 0x100 * i
CODE = 0x00800000            # Ghidra executes case i at CODE + 16 * i
CHUNK = 6000
M32 = 0xFFFFFFFF
DUMP = ["R%d" % i for i in range(8)] + ["P%d" % i for i in range(6)] + ["SP", "FP"] + \
       ["%s%d" % (g, i) for g in "IMBL" for i in range(4)] + ["RETS"]
OUT = DUMP + ["A0", "A1", "ASTAT"]
SKIP = re.compile(r"JUMP|CALL|RTS|RTI|RTX|RTN|RTE|LSETUP|IDLE|RAISE|EXCPT|\bCLI\b|\bSTI\b|TESTSET|DBG|PRNT|OUTC|ABORT|HLT|"
                  r"SYSCFG|RETI|RETX|RETN|RETE|SEQSTAT|USP|EMUDAT|CYCLES|\bL[CTB][01]\b|PREFETCH|FLUSH|SYNC|"
                  r"DISALGNEXCPT|SAA|BYTEOP")
EDGES = [0, 1, 2, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x80000001, 0x7FFF, 0x8000, 0xFFFF, 0x10000,
         0xFFFF8000, 0x00007FFF, 0x40000000, 0x3FFFFFFF, 0xC0000000]
HALVES = [0, 1, 0x7FFF, 0x8000, 0xFFFF, 0x8001, 0x7FFE, 0x4000]


def rval(rng):
    r = rng.random()
    if r < 0.35:
        return rng.getrandbits(32)
    if r < 0.55:
        return rng.randint(-64, 64) & M32
    if r < 0.75:
        return rng.choice(EDGES)
    h = [rng.choice(HALVES + [rng.getrandbits(16)]) for _ in range(2)]
    return h[0] << 16 | h[1]


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def pointer_fixups(words, win, regs):
    """Point base registers of immediate-offset loads/stores back into the window."""
    center = win + 0x80
    ptr = {0: "P0", 1: "P1", 2: "P2", 3: "P3", 4: "P4", 5: "P5", 6: "SP", 7: "FP"}
    w0 = words[0]
    slots = [w0] if not (w0 & 0xC000) == 0xC000 else []
    if (w0 & 0xF800) == 0xC800 and len(words) == 4:
        slots = [words[2], words[3]]
    for w in slots:
        if (w & 0xE000) == 0xA000 and (w & 0xFC00) != 0xB800:
            off, op = (w >> 6) & 0xF, (w >> 10) & 3
            regs[ptr[(w >> 3) & 7]] = (center - off * (4 if op in (0, 3) else 2)) & M32
    if (w0 & 0xFC00) == 0xE400 and len(words) >= 2:
        scale = (4, 2, 1, 1)[(w0 >> 6) & 3]
        regs[ptr[(w0 >> 3) & 7]] = (center - sext(words[1], 16) * scale) & M32


def dests(part):
    """Data registers assigned by one operation of a (packet) text."""
    out = set()
    m = re.match(r"\s*\(\s*R(\d)\s*,\s*R(\d)\s*\)\s*=", part)
    if m:
        return set(m.groups())
    for sub in part.split(","):
        m = re.match(r"\s*R(\d)(?:\.[LH])?\s*=", sub)
        if m:
            out.add(m.group(1))
    return out


def sim_undefined(words, regs, text):
    """Cases where the simulator's result is host-undefined or an out-of-bounds
    write, or the encoding itself is (a packet writing one register twice)."""
    parts = [dests(p) for p in text.split("||")]
    if len(parts) == 3 and (parts[0] & (parts[1] | parts[2]) or parts[1] & parts[2]):
        return True
    if len(parts) == 3 and parts[1] & set(re.findall(r"R(\d)", text.split("||")[2])):
        return True     # the simulator lets slot 2 see slot 1's load (writeback covers slot 0 only)
    w0 = words[0]
    if (w0 & 0xFC00) == 0x4000 and (w0 >> 6) & 0xF in (0, 1, 2) and regs["R%d" % ((w0 >> 3) & 7)] >> 31:
        return True     # Dreg shift by a negative count: C shift by a negative amount
    if (w0 & 0xF600) == 0xC000 and len(words) > 1 and w0 & 0xC == 0xC and (words[1] >> 6) & 7 == 7:
        return True     # 32-bit MAC1 result to R(dst+1) with dst=7: the simulator writes P0
    return False


def state(rng, words, win):
    regs = {}
    for i in range(8):
        regs["R%d" % i] = rval(rng)
    for r in ["P%d" % i for i in range(6)] + ["SP"] + ["I%d" % i for i in range(4)]:
        regs[r] = win + 0x80 + 4 * rng.randint(-8, 8)
    regs["FP"] = win + 0xC0
    for i in range(4):
        regs["M%d" % i] = (4 * rng.randint(-4, 4)) & M32 if rng.random() < 0.7 else rval(rng)
        regs["B%d" % i] = rval(rng)
        regs["L%d" % i] = 0
    regs["RETS"] = rng.getrandbits(32) & ~1
    for a in ("A0", "A1"):
        regs[a] = (rng.choice([0, 0xFF, rng.getrandbits(8)]) << 32) | rval(rng)
    regs["ASTAT"] = rng.getrandbits(32) & 0x030F316F
    pointer_fixups(words, win, regs)
    return regs


def load_corpus(mode, rng):
    """(words, text) of every decodable, testable encoding."""
    out = []
    for name in {"image": ["image"], "dsp": ["32"], "16": ["16"]}.get(mode, [n for n in ("image", "32", "16") if os.path.exists(os.path.join(W, f"build/isa/{n}.bin"))]):
        data = open(os.path.join(W, f"build/isa/{name}.bin"), "rb").read()
        rows = [line.rstrip("\n").split("\t", 2) for line in open(os.path.join(W, f"build/isa/{name}.ghidra.tsv"))]
        picks = []
        for i, (_, n, text) in enumerate(rows):
            n = int(n)
            if not n or SKIP.search(text.upper()):
                continue
            words = struct.unpack_from("<%dH" % (n // 2), data, i * 10)
            if name == "32" and (words[0] & 0xF000) != 0xC000 or name == "16" and n != 2:
                continue
            picks.append((words, text))
        if name == "32":
            picks = rng.sample(picks, min(len(picks), 20000))
        out += picks
    return out


def build_cases(mode, limit):
    rng = random.Random(7)
    cases = []
    for words, text in load_corpus(mode, rng):
        reps = 1 if "[" in text else 3
        for _ in range(reps):
            win = REGION + 0x100 * len(cases)
            cases.append((words, text, win, state(rng, words, win)))
    return cases[:limit] if limit else cases


def asm_case(i, words, regs, win):
    def imm(reg, v):
        return [f"{reg}.L = 0x{v & 0xFFFF:x};", f"{reg}.H = 0x{v >> 16 & 0xFFFF:x};"]
    s = [f"c{i}:", "P0.L = next; P0.H = next;"] + \
        [f"R0.L = e{i}; R0.H = e{i};", "[P0] = R0;"] + imm("R0", i) + ["RETN = R0;", "DBG RETN;"]
    for a in ("A0", "A1"):
        s += imm("R0", regs[a] & M32) + [f"{a}.W = R0;"] + imm("R0", regs[a] >> 32 & 0xFF) + [f"{a}.X = R0;"]
    s += imm("R0", regs["ASTAT"]) + ["ASTAT = R0;"] + imm("R0", regs["RETS"]) + ["RETS = R0;"]
    for r in DUMP[:-1]:
        s += imm(r, regs[r])
    s.append(".short " + ", ".join(f"0x{w:04x}" for w in words))
    s += [f"DBG {r};" for r in OUT]
    s += imm("P5", win) + ["R7 = 0;", "R5 = 0;", "P4 = 0x40 (Z);", f"LSETUP (s{i}, z{i}) LC0 = P4;",
                           f"s{i}: R6 = [P5++];", "R7 = R7 + R6;", f"z{i}: R5 = R5 ^ R6;", "DBG R7;", "DBG R5;",
                           f"e{i}:"]
    return "\n".join(s)


def run_sim(cases, lo, hi, region):
    """Run cases[lo:hi] in the simulator; returns {index: values} for completed cases."""
    src = os.path.join(B, "sim.s")
    with open(src, "w") as f:
        # Enter IVG15 (supervisor); EVT3 (exceptions) resumes at the next case.
        f.write(".text\n.global __start\n__start:\n"
                "P0.L = 0x200c; P0.H = 0xffe0; R0.L = skip; R0.H = skip; [P0] = R0;\n"
                "P0.L = 0x203c; P0.H = 0xffe0; R0.L = ivg15; R0.H = ivg15; [P0] = R0;\n"
                "R0 = 0x8000 (Z); STI R0; RAISE 15;\n"
                "P0.L = wait; P0.H = wait; RETI = P0; RTI;\nwait: JUMP wait;\n"
                "skip: P5.L = next; P5.H = next; P5 = [P5]; RETX = P5; RTX;\nivg15:\n")
        for i in range(lo, hi):
            words, _, win, regs = cases[i]
            f.write(asm_case(i, words, regs, win) + "\n")
        f.write("HLT;\n.data\n")
        f.write(f'.incbin "{region}", {0x100 * lo}, {0x100 * (hi - lo)}\nnext: .long 0\n')
    obj, elf = src[:-2] + ".o", src[:-2] + ".elf"
    subprocess.run([f"{TOOLS}/bfin-elf-as", src, "-o", obj], check=True)
    subprocess.run([f"{TOOLS}/bfin-elf-ld", "-e", "__start", "-Ttext=0x1000", f"-Tdata=0x{REGION + 0x100 * lo:x}",
                    obj, "-o", elf], check=True)
    # Slots of a parallel packet read their sources before any write lands; the
    # simulator only models that for data registers with this switch.
    env = dict(os.environ, BFIN_PARALLEL_WRITEBACK="1")
    out = subprocess.run([SIM, "--environment", "operating", elf], capture_output=True, text=True,
                         timeout=600, env=env).stdout
    done, cur, vals = {}, None, []
    for m in re.finditer(r"^DBG : (\S+) = (\S+)", out, re.M):
        if m.group(1) == "RETN":          # case marker
            cur, vals = int(m.group(2), 0), []
            continue
        vals.append(int(m.group(2), 0))
        if len(vals) == len(OUT) + 2:
            done[cur] = dict(zip(OUT, vals[:len(OUT)]), CK=(vals[-2], vals[-1]))
    return done


def run_ghidra(cases, region):
    tsv, res = os.path.join(B, "cases.tsv"), os.path.join(B, "ghidra.tsv")
    with open(tsv, "w") as f:
        for i, (words, _, win, regs) in enumerate(cases):
            hexb = struct.pack("<%dH" % len(words), *words).hex()
            kv = ",".join(f"{k}={v:x}" for k, v in regs.items())
            f.write(f"{i}\t{CODE + 16 * i:x}\t{hexb}\t{win:x}\t{kv}\n")
    env = dict(os.environ, JAVA_HOME=os.environ.get(
        "JAVA_HOME", "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"))
    proj = os.path.join(B, "proj")
    os.makedirs(proj, exist_ok=True)
    r = subprocess.run([f"{GHIDRA}/support/analyzeHeadless", proj, "sem", "-import", region, "-overwrite",
                        "-loader", "BinaryLoader", "-loader-baseAddr", hex(REGION),
                        "-processor", "Blackfin:LE:32:default", "-noanalysis",
                        "-scriptPath", os.path.join(W, "ghidra_scripts"),
                        "-postScript", "BfinEmuTest.java", tsv, res, "-deleteProject"],
                       capture_output=True, text=True, env=env)
    if r.returncode or not os.path.exists(res):
        sys.stderr.write(r.stdout[-3000:] + r.stderr[-3000:])
        raise SystemExit("ghidra failed")
    got = {}
    for line in open(res):
        f = line.rstrip("\n").split("\t")
        if f[1].startswith("ERR"):
            got[int(f[0])] = f[1]
            continue
        d = {k: int(v, 16) for k, v in (kv.split("=") for kv in f[1].split(","))}
        s, x = f[2].split(",")
        d["CK"] = (int(s, 16), int(x, 16))
        got[int(f[0])] = d
    return got


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    os.makedirs(B, exist_ok=True)
    cases = build_cases(mode, limit)
    region = os.path.join(B, "region.bin")
    with open(region, "wb") as f:
        f.write(random.Random(3).randbytes(0x100 * len(cases)))
    gh = run_ghidra(cases, region)
    sim = {}
    lo = 0
    for lo in range(0, len(cases), CHUNK):
        sim.update(run_sim(cases, lo, min(lo + CHUNK, len(cases)), region))
    stats = Counter()
    rejected = Counter()
    shapes = defaultdict(Counter)
    with open(os.path.join(B, "diff.tsv"), "w") as out:
        for i, (words, text, win, regs) in enumerate(cases):
            s, g = sim.get(i), gh.get(i)
            if s is None:
                stats["sim-rejected"] += 1
                rejected[re.sub(r"\b([RPIMBL][0-7]|SP|FP)\b", "X", re.sub(r"0x[0-9a-f]+", "N", text))] += 1
                continue
            if sim_undefined(words, regs, text):
                stats["sim-undefined"] += 1
                continue
            if isinstance(g, str):
                stats["ghidra-error"] += 1
                out.write(f"ghidra-error\t{text}\t{g}\n")
                continue
            if (words[0] & 0xF7FF) == 0xC411:
                # A1 + A0, A1 - A0: the simulator reads an uninitialized flag for V.
                s["ASTAT"] &= ~0x03000008
                g["ASTAT"] &= ~0x03000008
            bad = [k for k in OUT + ["CK"] if s[k] != g[k]]
            if not bad:
                stats["match"] += 1
                continue
            kind = "flags" if bad == ["ASTAT"] else "value"
            stats[kind] += 1
            detail = " ".join(f"{k}:sim={s[k] if k == 'CK' else hex(s[k])},gh={g[k] if k == 'CK' else hex(g[k])}" for k in bad)
            if kind == "flags":
                detail += f" diff={s['ASTAT'] ^ g['ASTAT']:#x}"
            ins = " ".join(f"{k}={regs[k]:#x}" for k in ("R0", "R1", "R2", "R3", "A0", "A1", "ASTAT"))
            out.write(f"{kind}\t{' '.join(f'{w:04x}' for w in words)}\t{text}\t{detail}\t{ins}\n")
            shape = re.sub(r"\b([RPIMBL][0-7]|SP|FP)\b", "X", re.sub(r"0x[0-9a-f]+", "N", text))
            shapes[kind][shape] += 1
    print(" ".join(f"{k}={v}" for k, v in stats.most_common()), file=sys.stderr)
    with open(os.path.join(B, "rejected.txt"), "w") as f:
        f.writelines(f"{n:7d}  {t}\n" for t, n in rejected.most_common())
    for kind, c in shapes.items():
        print(f"-- {kind}", file=sys.stderr)
        for sh, n in c.most_common(25):
            print(f"{n:7d}  {sh}", file=sys.stderr)


if __name__ == "__main__":
    assert sext(0xFFFF, 16) == -1 and sext(0x7FFF, 16) == 0x7FFF
    assert dests("(R1, R0) = SEARCH R2 (LT) ") == {"1", "0"}
    assert dests("R7 = R6.L * R0.H , R6.H = R6.H * R0.L") == {"6", "7"} and not dests(" [ I1--] = R7")
    main()
