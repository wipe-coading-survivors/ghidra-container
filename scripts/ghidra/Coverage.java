import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.TreeMap;

// Instruction density per 64KB bucket of the primary memory.
public class Coverage extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressSetView all = prog.getMemory().getLoadedAndInitializedAddressSet();
        TreeMap<Long, Integer> buckets = new TreeMap<>();
        long total = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(all, true);
             it.hasNext(); ) {
            long off = it.next().getAddress().getOffset();
            buckets.merge((off >> 16) << 16, 1, Integer::sum);
            total++;
        }
        for (java.util.Map.Entry<Long, Integer> e : buckets.entrySet()) {
            System.out.printf("BUCKET 0x%08x n=%d%n", (long) e.getKey(), (int) e.getValue());
            println("BUCKET 0x" + String.format("%08x", e.getKey()) + " n=" + e.getValue());
        }
        println("TOTAL " + total);
        println("DONE");
    }
}
