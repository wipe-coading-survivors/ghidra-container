import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;

// For each "addr back fwd" line in /work/build/ghidra-scan.txt prints the
// disassembly window [addr-back, addr+fwd]; undisassembled gaps shown as bytes.
public class Around extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Set<String> lines = new LinkedHashSet<>(
            Files.readAllLines(Paths.get("/work/build/ghidra-scan.txt")));
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] t = line.split("\\s+");
            long a = Long.parseLong(t[0].replaceFirst("^0x", ""), 16);
            long back = t.length > 1 ? Long.parseLong(t[1].replaceFirst("^0x", ""), 16) : 0x60;
            long fwd = t.length > 2 ? Long.parseLong(t[2].replaceFirst("^0x", ""), 16) : 0x30;
            Address lo = af.getDefaultAddressSpace().getAddress(a - back);
            Address hi = af.getDefaultAddressSpace().getAddress(a + fwd);
            println("==== around 0x" + Long.toHexString(a) + " [" + lo + "," + hi + "]");
            Address cur = lo;
            while (cur.compareTo(hi) < 0) {
                Instruction ins = prog.getListing().getInstructionAt(cur);
                if (ins != null) {
                    String mark = cur.getOffset() == a ? " <<<" : "";
                    println("  " + cur + "  " + ins.toString() + mark);
                    cur = ins.getMaxAddress().add(1);
                } else {
                    byte[] b = new byte[8];
                    int got = 0;
                    try {
                        got = prog.getMemory().getBytes(cur, b);
                    } catch (Exception e) { /* boundary */ }
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < got; i++) sb.append(String.format("%02x ", b[i]));
                    println("  " + cur + "  db: " + sb);
                    cur = cur.add(1);
                }
            }
        }
        println("DONE");
    }
}
