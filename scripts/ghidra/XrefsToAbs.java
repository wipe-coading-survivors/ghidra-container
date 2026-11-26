import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.List;

// XrefsTo but with a load-base adjustment: targets in /work/build/ghidra-scan.txt
// are SECTREL offsets; the iRISC code references them at (BASE + sectrel) where
// BASE defaults to 0x800000 (override via first "#base=0xNNN" line). Skips the
// memory.contains check so out-of-mapped-range targets still resolve.
public class XrefsToAbs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        long base = 0x800000L;
        List<Long> targets = new java.util.ArrayList<>();
        for (String line : java.nio.file.Files.readAllLines(
                java.nio.file.Paths.get("/work/build/ghidra-scan.txt"))) {
            line = line.trim();
            if (line.startsWith("#base=")) {
                base = Long.parseLong(line.substring(6).replaceFirst("^0x", ""), 16);
                continue;
            }
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("0x") || line.startsWith("0X")) line = line.substring(2);
            targets.add(Long.parseLong(line, 16));
        }
        println("BASE 0x" + Long.toHexString(base));
        for (long t : targets) {
            long abs = base + t;
            Address a = af.getDefaultAddressSpace().getAddress(abs);
            ReferenceIterator it = prog.getReferenceManager().getReferencesTo(a);
            int n = 0;
            for (; it.hasNext(); ) {
                Reference r = it.next();
                n++;
                Address from = r.getFromAddress();
                Instruction ins = prog.getListing().getInstructionAt(from);
                Function fn = prog.getFunctionManager().getFunctionContaining(from);
                println("  XREF from=" + from
                    + " type=" + r.getReferenceType()
                    + " fn=" + (fn == null ? "<none>" : fn.getEntryPoint())
                    + " ins=" + (ins == null ? "?" : ins.toString()));
            }
            println("TARGET sectrel=0x" + Long.toHexString(t)
                + " abs=0x" + Long.toHexString(abs) + " n=" + n);
        }
        println("DONE");
    }
}
