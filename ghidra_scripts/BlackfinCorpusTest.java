// SPDX-License-Identifier: GPL-2.0-or-later
// @category CDJ.Blackfin

import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/** Corpus-backed decoder coverage and structural regression checks. */
public class BlackfinCorpusTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String mode = getScriptArgs().length == 0 ? "l1" : getScriptArgs()[0];
        if (mode.equals("l1") || mode.equals("coverage")) {
            checkRange(0xffa08000L, 0xffa08585L, mode.equals("l1"), "L1");
        }
        else if (mode.equals("app")) {
            checkRange(0x00d00000L, 0x00d3ffffL, false, "APP_D0_D4");
        }
        else if (mode.equals("packet")) {
            checkParallelPacket();
        }
        else {
            throw new IllegalArgumentException("expected l1, coverage, app, or packet, got " + mode);
        }
    }

    private void checkRange(long startValue, long endValue, boolean assertCorpus, String label) throws Exception {
        Address start = toAddr(startValue);
        Address end = toAddr(endValue);
        AddressSet corpus = new AddressSet(start, end);
        Map<String, Integer> mnemonics = new TreeMap<>();
        int instructions = 0;
        int bytes = 0;
        int bfin16 = 0;
        int bfin32 = 0;
        int dsp32 = 0;
        int multi = 0;
        int unknownParallelSlot = 0;

        Address cursor = start;
        while (cursor.compareTo(end) <= 0) {
            Instruction instruction = currentProgram.getListing().getInstructionAt(cursor);
            if (instruction == null) {
                new DisassembleCommand(cursor, corpus, false).applyTo(currentProgram, monitor);
                instruction = currentProgram.getListing().getInstructionAt(cursor);
            }
            if (instruction == null) {
                throw new AssertionError("failed to decode at " + cursor);
            }
            String mnemonic = instruction.getMnemonicString();
            mnemonics.merge(mnemonic, 1, Integer::sum);
            if (mnemonic.equals("BFIN16")) bfin16++;
            if (mnemonic.equals("BFIN32")) bfin32++;
            if (mnemonic.equals("DSP32")) dsp32++;
            if (mnemonic.equals("DSP32_MULTI")) {
                multi++;
                if (instruction.toString().contains("PAR16")) unknownParallelSlot++;
            }
            if (label.equals("L1") && !assertCorpus &&
                    (mnemonic.equals("BFIN16") || mnemonic.equals("DSP32"))) {
                println("BLACKFIN_FALLBACK " + cursor + " len=" + instruction.getLength() +
                    " bytes=" + bytesAt(cursor, instruction.getLength()));
            }
            instructions++;
            bytes += instruction.getLength();
            cursor = cursor.add(instruction.getLength());
        }

        println("BLACKFIN_" + label + "_COVERAGE instructions=" + instructions + " bytes=" + bytes +
            " BFIN16=" + bfin16 + " BFIN32=" + bfin32 + " DSP32=" + dsp32 +
            " DSP32_MULTI=" + multi + " unknownParallelSlot=" + unknownParallelSlot +
            " mnemonics=" + mnemonics);
        if (assertCorpus) {
            assertStarts(0xffa0801cL, "LC0 = R7", 2);
            assertStarts(0xffa08028L, "I0.L =", 4);
            assertStarts(0xffa08038L, "[I0] = R7", 2);
            assertStarts(0xffa08052L, "LSETUP", 4);
            assertStarts(0xffa080aeL, "[--SP] = RETI", 2);
            assertStarts(0xffa08266L, "R0 = [I2++]", 2);
            assertStarts(0xffa08392L, "R1 = [P0 +", 4);
            println("BLACKFIN_L1_CORPUS_OK");
        }
    }

    private String bytesAt(Address address, int length) throws Exception {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < length; i++) {
            if (i != 0) out.append(' ');
            out.append(String.format("%02x", currentProgram.getMemory().getByte(address.add(i)) & 0xff));
        }
        return out.toString();
    }

    private void checkParallelPacket() throws Exception {
        Address packet = toAddr(0x00d003b2L);
        AddressSet body = new AddressSet(packet, packet.add(7));
        if (!new DisassembleCommand(packet, body, false).applyTo(currentProgram, monitor)) {
            throw new AssertionError("parallel packet disassembly failed");
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(packet);
        if (instruction == null) throw new AssertionError("no packet at " + packet);
        String rendered = instruction.toString();
        if (instruction.getLength() != 8) {
            throw new AssertionError("packet length expected 8, got " + instruction.getLength());
        }
        String normalized = rendered.replace(" ", "");
        if (!rendered.startsWith("DSP32_MULTI") || !normalized.contains("[SP+")) {
            throw new AssertionError("parallel memory slot not decoded: " + rendered);
        }
        boolean hasStore = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.STORE) hasStore = true;
        }
        if (!hasStore) throw new AssertionError("parallel memory slot has no STORE p-code");
        println(packet + "  " + rendered);
        println("BLACKFIN_PACKET_OK");
    }

    private void assertStarts(long addressValue, String expected, int length) {
        Address address = toAddr(addressValue);
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction == null) throw new AssertionError("no instruction at " + address);
        String rendered = instruction.toString();
        String normalized = rendered.replace(" ", "");
        String normalizedExpected = expected.replace(" ", "");
        if (!normalized.startsWith(normalizedExpected) || instruction.getLength() != length) {
            throw new AssertionError(address + ": expected '" + expected + "' len=" + length +
                ", got '" + rendered + "' len=" + instruction.getLength());
        }
    }
}
