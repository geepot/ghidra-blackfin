// Decode one instruction at every fixed-stride slot of the current program without
// following flow, and write "address<TAB>length<TAB>text" (length 0 = no decode).
// Every slot that matches a constructor but cannot build p-code (for example an
// attach-table hole) is also listed in <output.tsv>.pcode as "address<TAB>error".
// Used by tools/bfin_isatest.py to compare the SLEIGH decoder with GNU objdump.
// Args: <output.tsv> <stride>
//@category Blackfin

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.lang.UnknownInstructionException;

import java.io.PrintWriter;

public class DisasmSlots extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        int stride = Integer.parseInt(args[1]);
        var block = currentProgram.getMemory().getBlocks()[0];
        long size = block.getSize();
        try (PrintWriter w = new PrintWriter(args[0]); PrintWriter p = new PrintWriter(args[0] + ".pcode")) {
            for (long off = 0; off + stride <= size; off += stride) {
                Address a = block.getStart().add(off);
                String text = "";
                int len = 0;
                try {
                    // Parse directly: PseudoDisassembler turns every parse error into null.
                    var buf = new MemoryBufferImpl(currentProgram.getMemory(), a);
                    var ctx = new PseudoDisassemblerContext(currentProgram.getProgramContext());
                    var proto = currentProgram.getLanguage().parse(buf, ctx, false);
                    var i = new PseudoInstruction(currentProgram, a, proto, buf, ctx);
                    i.getPcode();
                    len = i.getLength();
                    text = i.toString();
                }
                catch (Exception e) {
                    // No matching constructor is a clean "undecodable"; anything else
                    // (e.g. "Failed to resolve varnode") is a broken constructor.
                    if (!(e instanceof UnknownInstructionException && String.valueOf(e.getMessage()).startsWith("Unable to resolve constructor")))
                        p.println(a.getOffset() + "\t" + e);
                }
                w.println(a.getOffset() + "\t" + len + "\t" + text);
            }
        }
    }
}
