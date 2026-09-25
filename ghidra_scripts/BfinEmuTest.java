// Execute single Blackfin instructions in Ghidra's p-code emulator for
// scripts/bfin_semtest.py, which runs the same cases in the GNU simulator.
// Input lines:  index <TAB> address <TAB> hexbytes <TAB> window <TAB> reg=hex,reg=hex,...
// Output lines: index <TAB> reg=hex,... (after one step) <TAB> checksum words, or "index<TAB>ERR <message>".
// The current program holds the memory image; every case only touches its window.
// Args: <cases.tsv> <results.tsv>
//@category Blackfin

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintWriter;
import java.math.BigInteger;

public class BfinEmuTest extends GhidraScript {
    static final String[] DUMP = {
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "P0", "P1", "P2", "P3", "P4", "P5", "SP", "FP",
        "I0", "I1", "I2", "I3", "M0", "M1", "M2", "M3", "B0", "B1", "B2", "B3", "L0", "L1", "L2", "L3", "RETS" };
    static final String[] FLAGS = { "AZ", "AN", "AC0_COPY", "V_COPY", "CC", "AQ", "RND_MOD", "AC0", "AC1",
        "AV0", "AV0S", "AV1", "AV1S", "V", "VS" };
    static final int[] FLAG_BITS = { 0, 1, 2, 3, 5, 6, 8, 12, 13, 16, 17, 18, 19, 24, 25 };
    static final BigInteger M40 = BigInteger.ONE.shiftLeft(40).subtract(BigInteger.ONE);

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try (BufferedReader in = new BufferedReader(new FileReader(args[0]));
             PrintWriter out = new PrintWriter(args[1])) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] f = line.split("\t");
                String idx = f[0];
                try {
                    long pc = Long.parseLong(f[1], 16);
                    Address at = ram.getAddress(pc);
                    emu.writeMemory(at, hex(f[2]));
                    long window = Long.parseLong(f[3], 16);
                    for (String kv : f[4].split(",")) {
                        String[] p = kv.split("=");
                        BigInteger v = new BigInteger(p[1], 16);
                        if (p[0].equals("ASTAT")) {
                            for (int i = 0; i < FLAGS.length; i++) {
                                emu.writeRegister(FLAGS[i], v.testBit(FLAG_BITS[i]) ? 1 : 0);
                            }
                            emu.writeRegister("ASTAT_RSV", 0);
                        }
                        else {
                            emu.writeRegister(p[0], v);
                        }
                    }
                    emu.writeRegister(emu.getPCRegister(), pc);
                    if (!emu.step(monitor)) {
                        out.println(idx + "\tERR " + emu.getLastError());
                        continue;
                    }
                    StringBuilder sb = new StringBuilder(idx).append('\t');
                    for (String r : DUMP) {
                        sb.append(r).append('=').append(emu.readRegister(r).toString(16)).append(',');
                    }
                    sb.append("A0=").append(emu.readRegister("A0").and(M40).toString(16)).append(',');
                    sb.append("A1=").append(emu.readRegister("A1").and(M40).toString(16)).append(',');
                    long astat = emu.readRegister("ASTAT_RSV").longValue();
                    for (int i = 0; i < FLAGS.length; i++) {
                        if (emu.readRegister(FLAGS[i]).signum() != 0) {
                            astat |= 1L << FLAG_BITS[i];
                        }
                    }
                    sb.append("ASTAT=").append(Long.toHexString(astat));
                    // Window checksum as the simulator computes it: 32-bit sum and xor of 64 words.
                    byte[] w = emu.readMemory(ram.getAddress(window), 256);
                    int sum = 0, xor = 0;
                    for (int i = 0; i < 256; i += 4) {
                        int v = (w[i] & 0xff) | (w[i + 1] & 0xff) << 8 | (w[i + 2] & 0xff) << 16 | (w[i + 3] & 0xff) << 24;
                        sum += v;
                        xor ^= v;
                    }
                    sb.append('\t').append(Integer.toHexString(sum)).append(',').append(Integer.toHexString(xor));
                    out.println(sb);
                }
                catch (Exception e) {
                    out.println(idx + "\tERR " + e);
                }
            }
        }
        finally {
            emu.dispose();
        }
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }
}
