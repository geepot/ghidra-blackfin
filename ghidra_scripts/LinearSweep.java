// Decode a contiguous Blackfin code range and report instruction lengths.
// Args: <start-hex> <end-exclusive-hex> <output.tsv>
//@category Blackfin

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

import java.io.PrintWriter;
import java.util.Map;
import java.util.TreeMap;

public class LinearSweep extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        long start = Long.parseUnsignedLong(args[0], 16);
        long end = Long.parseUnsignedLong(args[1], 16);
        long pc = start;
        Map<Integer, Integer> lengths = new TreeMap<>();
        try (PrintWriter out = new PrintWriter(args[2])) {
            while (Long.compareUnsigned(pc, end) < 0) {
                Address at = toAddr(pc);
                if (!currentProgram.getMemory().contains(at)) {
                    throw new IllegalStateException("unmapped address " + at);
                }
                Instruction instruction = currentProgram.getListing().getInstructionAt(at);
                if (instruction == null) {
                    disassemble(at);
                    instruction = currentProgram.getListing().getInstructionAt(at);
                }
                if (instruction == null) {
                    throw new IllegalStateException("undecoded address " + at);
                }
                int length = instruction.getLength();
                if (length <= 0 || Long.compareUnsigned(pc + length, end) > 0) {
                    throw new IllegalStateException("instruction crosses end at " + at);
                }
                lengths.merge(length, 1, Integer::sum);
                out.println(Long.toHexString(pc) + "\t" + length + "\t" + instruction);
                pc += length;
            }
        }
        println("Linear sweep " + Long.toHexString(start) + ".." + Long.toHexString(end)
            + ": " + lengths + " instructions=" + lengths.values().stream().mapToInt(Integer::intValue).sum());
    }
}
