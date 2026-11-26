import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

// Dump all references FROM decoded instructions TO the absolute iRISC data zone
// [0x800000+0x300000, 0x800000+size). Buckets by 0x400 page: count + one sample
// (from-addr, instruction). Also reports any ref landing in the string sub-zone.
public class DumpDataRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        long base = 0x800000L;
        long lo = base + 0x300000L;
        long hi = base + 0x34eae0L;
        Map<Long, Integer> pageCnt = new TreeMap<>();
        Map<Long, String> sample = new HashMap<>();
        int total = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            for (Reference r : prog.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                Address to = r.getToAddress();
                long t = to.getOffset();
                if (t < lo || t >= hi) continue;
                long page = t & ~0x3ffL;
                pageCnt.merge(page, 1, Integer::sum);
                total++;
                if (!sample.containsKey(page)) {
                    sample.put(page, ins.getAddress().toString() + " :: " + ins.toString());
                }
            }
        }
        for (Map.Entry<Long, Integer> e : pageCnt.entrySet()) {
            println("PAGE 0x" + Long.toHexString(e.getKey())
                + " (sectrel 0x" + Long.toHexString(e.getKey() - base) + ") n=" + e.getValue()
                + "  e.g. " + sample.get(e.getKey()));
        }
        println("TOTAL_DATA_REFS " + total + " pages=" + pageCnt.size());
        println("DONE");
    }
}
