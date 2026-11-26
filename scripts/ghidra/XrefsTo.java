import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.List;

// Prints all references (any space) to the target offsets from
// /work/build/ghidra-scan.txt (one hex per line).
public class XrefsTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        List<Long> targets = new java.util.ArrayList<>();
        for (String line : java.nio.file.Files.readAllLines(
                java.nio.file.Paths.get("/work/build/ghidra-scan.txt"))) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("0x") || line.startsWith("0X")) line = line.substring(2);
            targets.add(Long.parseLong(line, 16));
        }
        for (long t : targets) {
            Address a = af.getDefaultAddressSpace().getAddress(t);
            if (a == null || !prog.getMemory().contains(a)) {
                println("TARGET 0x" + Long.toHexString(t) + " OUT-OF-RANGE");
                continue;
            }
            ReferenceIterator it = prog.getReferenceManager().getReferencesTo(a);
            int n = 0;
            for (; it.hasNext(); ) {
                Reference r = it.next();
                n++;
                Address from = r.getFromAddress();
                Instruction ins = prog.getListing().getInstructionAt(from);
                Function fn = prog.getFunctionManager().getFunctionContaining(from);
                println("  XREF from=" + from + " space=" + r.getFromAddress().getAddressSpace().getName()
                    + " type=" + r.getReferenceType()
                    + " fn=" + (fn == null ? "<none>" : fn.getEntryPoint())
                    + " ins=" + (ins == null ? "?" : ins.toString()));
            }
            println("TARGET 0x" + Long.toHexString(t) + " n=" + n);
        }
        println("DONE");
    }
}
