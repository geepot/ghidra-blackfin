// Write every instruction of the current program as "address<TAB>length<TAB>text"
// (plus the containing function) for cross-checking against another disassembler.
// Args: <output.tsv>
//@category CDJ2000NXS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

import java.io.PrintWriter;

public class ExportInstructions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        try (PrintWriter w = new PrintWriter(getScriptArgs()[0])) {
            for (Instruction i : currentProgram.getListing().getInstructions(true)) {
                var f = getFunctionContaining(i.getAddress());
                w.println(i.getAddress().getOffset() + "\t" + i.getLength() + "\t" + i + "\t"
                    + (f == null ? "" : f.getEntryPoint().getOffset()));
            }
        }
    }
}
