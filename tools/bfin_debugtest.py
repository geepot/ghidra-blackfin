#!/usr/bin/env python3
"""Check the 40 reserved debug-register encodings against objdump's spelling."""
import os
import struct

from bfin_isatest import BASE, SLOT, W, ghidra


def main():
    selectors = [36, 37, *range(40, 48)]
    cases = []
    for function, name in ((0, "DBG"), (1, "PRNT")):
        for selector in selectors:
            cases.append((0xf800 | function << 6 | selector, 0,
                          2, f"{name} ...... Illegal register ......."))
    for function, name in ((2, "DBGAL"), (3, "DBGAH")):
        for selector in selectors:
            cases.append((0xf000 | function << 6 | selector, 0x1234,
                          4, f"{name} (...... Illegal register .......,0x1234)"))
    os.makedirs(os.path.join(W, "build/isa"), exist_ok=True)
    binary = os.path.join(W, "build/isa/debug-reserved.bin")
    with open(binary, "wb") as out:
        for first, second, _, _ in cases:
            out.write(struct.pack("<5H", first, second, 0, 0, 0))
    decoded = ghidra(binary, os.path.join(W, "build/isa/debug-reserved.tsv"))
    for i, (_, _, length, text) in enumerate(cases):
        got = decoded.get(BASE + i * SLOT)
        if got != (length, text):
            raise SystemExit(f"case {i}: got {got}, expected {(length, text)}")
    print(f"{len(cases)} reserved debug-register encodings passed")


if __name__ == "__main__":
    main()
