// SPDX-License-Identifier: GPL-2.0-or-later
// @category CDJ.Blackfin

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;

public class BlackfinSmokeTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguageID().toString().equals("Blackfin:LE:32:default")) {
            throw new AssertionError("wrong language: " + currentProgram.getLanguageID());
        }

        Address start = toAddr(0x00d09a00L);
        Address end = toAddr(0x00d09b1eL);
        AddressSet body = new AddressSet(start, end);
        if (!new DisassembleCommand(start, body, true).applyTo(currentProgram, monitor)) {
            throw new AssertionError("disassembly command failed");
        }
        if (!new DisassembleCommand(toAddr(0x00d09a34L), body, true).applyTo(currentProgram, monitor)) {
            throw new AssertionError("second disassembly command failed");
        }
        if (!new DisassembleCommand(toAddr(0x00d09ab0L), body, true).applyTo(currentProgram, monitor)) {
            throw new AssertionError("third disassembly command failed");
        }

        Map<Long, String> expected = new LinkedHashMap<>();
        expected.put(0x00d09a04L, "CALL 0x00d4837c");
        expected.put(0x00d09a16L, "CALL 0x00d0820a");
        expected.put(0x00d09a34L, "LINK");
        expected.put(0x00d09a38L, "P1.L =");
        expected.put(0x00d09a3cL, "P1.H =");
        expected.put(0x00d09a40L, "R0");
        expected.put(0x00d09a42L, "R1");
        expected.put(0x00d09a44L, "CC");
        expected.put(0x00d09a46L, "IF CC JUMP");
        expected.put(0x00d09a52L, "JUMP.S");
        expected.put(0x00d09a80L, "RTS");
        expected.put(0x00d09ab4L, "[--SP]");
        expected.put(0x00d09b18L, "R7");

        for (Map.Entry<Long, String> check : expected.entrySet()) {
            Address address = toAddr(check.getKey());
            Instruction instruction = currentProgram.getListing().getInstructionAt(address);
            if (instruction == null) {
                throw new AssertionError("no instruction at " + address);
            }
            String rendered = instruction.toString();
            if (!rendered.startsWith(check.getValue())) {
                throw new AssertionError(address + ": expected " + check.getValue() + ", got " + rendered);
            }
            println(address + "  " + rendered);
        }

        assertFlow(0x00d09a04L, 0x00d4837cL);
        assertFlow(0x00d09a16L, 0x00d0820aL);

        println("BLACKFIN_SMOKE_OK");
    }

    private void assertFlow(long sourceValue, long targetValue) {
        Instruction instruction = currentProgram.getListing().getInstructionAt(toAddr(sourceValue));
        Address wanted = toAddr(targetValue);
        for (Address target : instruction.getFlows()) {
            if (target.equals(wanted)) {
                return;
            }
        }
        throw new AssertionError(toAddr(sourceValue) + ": missing direct flow to " + wanted);
    }
}
