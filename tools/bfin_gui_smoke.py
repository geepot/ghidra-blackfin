#!/usr/bin/env python3
"""Check the stock CDJ GUI L1 bootstrap from its LDR image with Ghidra.

    python3 tools/bfin_gui_smoke.py ../cdj2000nxs-research/extracted/gui.image.bin

The input starts with pre-BF54x LDR block headers, not a flat memory image.
No firmware is committed; temporary files go under build/gui.
"""
import os
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GHIDRA = Path(os.environ.get("GHIDRA", "/opt/homebrew/opt/ghidra/libexec"))
START, END = 0xFFA08000, 0xFFA08586
HEADER = struct.Struct("<IIH")


def l1_code(image):
    cursor = 0
    code = bytearray(END - START)
    covered = bytearray(len(code))
    blocks = 0
    l1_blocks = 0
    while cursor + HEADER.size <= len(image):
        address, count, flags = HEADER.unpack_from(image, cursor)
        payload = cursor + HEADER.size
        next_cursor = payload if flags & 1 else payload + count
        if next_cursor > len(image):
            raise ValueError(f"LDR block {blocks} overruns image")
        if START <= address < END:
            if flags & 1 or address + count > END:
                raise ValueError(f"unexpected L1 block {blocks}")
            offset = address - START
            if any(covered[offset:offset + count]):
                raise ValueError(f"overlapping L1 block {blocks}")
            code[offset:offset + count] = image[payload:next_cursor]
            covered[offset:offset + count] = bytes([1]) * count
            l1_blocks += 1
        cursor = next_cursor
        blocks += 1
        if flags & 0x8000:
            if not all(covered):
                raise ValueError("L1 bootstrap has gaps")
            return bytes(code), blocks, l1_blocks
    raise ValueError("LDR stream has no final block")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    image = Path(sys.argv[1]).read_bytes()
    code, blocks, l1_blocks = l1_code(image)
    directory = ROOT / "build/gui"
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "l1.bin"
    listing = directory / "l1.tsv"
    binary.write_bytes(code)
    listing.unlink(missing_ok=True)
    command = [str(GHIDRA / "support/analyzeHeadless"), str(directory), "gui-smoke",
               "-import", str(binary), "-loader", "BinaryLoader",
               "-loader-baseAddr", hex(START), "-processor", "Blackfin:LE:32:default",
               "-noanalysis", "-scriptPath", str(ROOT / "ghidra_scripts"),
               "-postScript", "LinearSweep.java", f"{START:x}", f"{END:x}", str(listing),
               "-deleteProject"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode or not listing.exists():
        raise SystemExit(result.stdout[-3000:] + result.stderr[-1000:])
    lengths = Counter(int(row.split("\t", 2)[1]) for row in listing.read_text().splitlines())
    if lengths != {2: 367, 4: 170}:
        raise SystemExit(f"unexpected GUI bootstrap lengths: {dict(lengths)}")
    print(f"GUI LDR: {blocks} blocks, {l1_blocks} L1 blocks, {len(code)} bytes; "
          f"Ghidra: {sum(lengths.values())} instructions ({dict(lengths)})")


if __name__ == "__main__":
    main()
