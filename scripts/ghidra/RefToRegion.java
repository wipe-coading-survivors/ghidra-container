import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

// For each address in [lo,hi) from /work/build/ghidra-range.txt, print
// getReferencesTo(addr). Reliable per-address xref lookup.
public class RefToRegion extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Path p = Paths.get("/work/build/ghidra-range.txt");
        String[] t = Files.readString(p).trim().split("\\s+");
        long lo = Long.parseLong(t[0].replaceFirst("^0x", ""), 16);
        long hi = Long.parseLong(t[1].replaceFirst("^0x", ""), 16);
        Address base = prog.getImageBase();
        int n = 0;
        for (long a = lo; a < hi; a += 4) {
            Address addr = base.add(a);
            ReferenceIterator it = prog.getReferenceManager().getReferencesTo(addr);
            for (; it.hasNext(); ) {
                Reference r = it.next();
                Address from = r.getFromAddress();
                Instruction ins = prog.getListing().getInstructionAt(from);
                println("REF from=0x" + Long.toHexString(from.getOffset())
                    + " -> 0x" + Long.toHexString(a)
                    + " " + r.getReferenceType()
                    + " ins=" + (ins == null ? "?" : ins.toString()));
                n++;
            }
        }
        println("NREF " + n + " region=[" + Long.toHexString(lo)
            + "," + Long.toHexString(hi) + ")");
        println("DONE");
    }
}
