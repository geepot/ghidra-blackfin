// Decode one instruction at every fixed-stride slot of the current program without
// following flow, and write "address<TAB>length<TAB>text" (length 0 = no decode).
// Used by scripts/bfin_isatest.py to compare the SLEIGH decoder with GNU objdump.
// Args: <output.tsv> <stride>
//@category Blackfin

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;

import java.io.PrintWriter;

public class DisasmSlots extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        int stride = Integer.parseInt(args[1]);
        PseudoDisassembler pd = new PseudoDisassembler(currentProgram);
        var block = currentProgram.getMemory().getBlocks()[0];
        long size = block.getSize();
        try (PrintWriter w = new PrintWriter(args[0])) {
            for (long off = 0; off + stride <= size; off += stride) {
                Address a = block.getStart().add(off);
                String text;
                int len;
                try {
                    PseudoInstruction i = pd.disassemble(a);
                    len = i == null ? 0 : i.getLength();
                    text = i == null ? "" : i.toString();
                }
                catch (Exception e) {
                    len = 0;
                    text = "";
                }
                w.println(a.getOffset() + "\t" + len + "\t" + text);
            }
        }
    }
}
