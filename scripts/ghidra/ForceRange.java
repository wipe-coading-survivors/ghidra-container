import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

// Force sequential disassembly of [lo,hi) ranges (one "lo hi" per line in
// /work/build/ghidra-scan.txt), printing the resulting instructions.
// Undecodable bytes advance by 1 (x86 re-syncs fast).
public class ForceRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        List<String> lines = Files.readAllLines(Paths.get("/work/build/ghidra-scan.txt"));
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] t = line.split("\\s+");
            long lo = Long.parseLong(t[0].replaceFirst("^0x", ""), 16);
            long hi = Long.parseLong(t[1].replaceFirst("^0x", ""), 16);
            println("==== range 0x" + Long.toHexString(lo) + " 0x" + Long.toHexString(hi));
            Address cur = af.getDefaultAddressSpace().getAddress(lo);
            Address end = af.getDefaultAddressSpace().getAddress(hi);
            while (cur.compareTo(end) < 0) {
                Instruction ins = prog.getListing().getInstructionAt(cur);
                if (ins == null) {
                    disassemble(cur);
                    ins = prog.getListing().getInstructionAt(cur);
                }
                if (ins != null && ins.getLength() > 0) {
                    println("  " + cur + "  " + ins.toString());
                    cur = ins.getMaxAddress().add(1);
                } else {
                    cur = cur.add(1);
                }
            }
        }
        println("DONE");
    }
}
