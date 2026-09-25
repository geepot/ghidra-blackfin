#!/usr/bin/env python3
"""Directed circular-DAG p-code checks (uses the installed Ghidra extension).

    python3 tools/bfin_dagtest.py

Runs real instructions in Ghidra's p-code emulator, including both sides of a
wrap, negative M-register increments, indexed loads and the L=0 linear case.
When BFIN_BINUTILS and BFIN_RUN point to a GNU Blackfin toolchain, also checks
the same cases against the GNU simulator.
"""
import os
import random
import shutil
import struct

from bfin_semtest import B, M32, REGION, SIM, TOOLS, run_ghidra, run_sim, state


def main():
    os.makedirs(B, exist_ok=True)
    cases = []
    checks = []
    rng = random.Random(29)
    specs = [
        # word, index, offset from B, length, M0, expected offset, loaded R0?
        (0x9f68, 0, 12, 16, 0, 0, False),    # I0 += 4
        (0x9f6c, 0, 0, 16, 0, 12, False),    # I0 -= 4
        (0x9e60, 0, 0, 16, -4, 12, False),   # I0 += M0
        (0x9e70, 0, 0, 16, 4, 12, False),    # I0 -= M0
        (0x9c00, 0, 12, 16, 0, 0, True),     # R0 = [I0++]
        (0x9c80, 0, 0, 16, 0, 12, True),     # R0 = [I0--]
        (0x9d80, 0, 0, 16, -4, 12, True),    # R0 = [I0 ++ M0]
        (0x9c08, 1, 12, 16, 0, 0, True),     # R0 = [I1++]
        (0x9c10, 2, 0, 16, 0, 4, True),      # R0 = [I2++]
        (0x9c18, 3, 12, 16, 0, 0, True),     # R0 = [I3++]
        (0x9f68, 0, 12, 0, 0, 16, False),    # L=0, B retains an old value
        (0x9f68, 0, 12, 16, 0, 0, False, 0xfffffff0),  # high-address wrap
        (0x9f6c, 0, 0, 16, 0, 12, False, 0xfffffff0),
    ]
    region = bytearray(rng.randbytes(0x100 * len(specs)))
    for idx, spec in enumerate(specs):
        word, index, offset, length, m, expected, loaded, *base_override = spec
        win = REGION + idx * 0x100
        base = base_override[0] if base_override else win + 0x80
        regs = state(rng, (word,), win)
        regs[f"I{index}"] = (base + offset) & M32
        regs[f"B{index}"] = base
        regs[f"L{index}"] = length
        regs["M0"] = m & M32
        # The indexed load uses the pre-modification address.
        if loaded:
            value = struct.unpack_from("<I", region, idx * 0x100 + 0x80 + offset)[0]
        else:
            value = None
        cases.append(((word,), "DAG directed", win, regs))
        checks.append((f"I{index}", (base + expected) & M32, value))
    region_path = os.path.join(B, "dag-region.bin")
    with open(region_path, "wb") as f:
        f.write(region)
    got = run_ghidra(cases, region_path)
    sim = run_sim(cases, 0, len(cases), region_path) if os.path.isfile(f"{TOOLS}/bfin-elf-as") and shutil.which(SIM) else None
    errors = []
    for idx, (register, expected, loaded) in enumerate(checks):
        result = got[idx]
        if isinstance(result, str):
            errors.append(f"case {idx}: {result}")
            continue
        if result[register] != expected:
            errors.append(f"case {idx}: {register}={result[register]:#x}, expected {expected:#x}")
        if loaded is not None and result["R0"] != loaded:
            errors.append(f"case {idx}: R0={result['R0']:#x}, expected {loaded:#x}")
        if sim is not None:
            oracle = sim.get(idx)
            if oracle is None:
                errors.append(f"case {idx}: GNU simulator rejected the case")
            elif oracle[register] != result[register] or loaded is not None and oracle["R0"] != result["R0"]:
                errors.append(f"case {idx}: GNU simulator disagrees on {register} or R0")
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"{len(cases)} circular-DAG emulator cases passed" + (" against the GNU simulator" if sim is not None else ""))


if __name__ == "__main__":
    main()
