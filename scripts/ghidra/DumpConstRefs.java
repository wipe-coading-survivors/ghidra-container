import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.util.HashMap;
import java.util.Map;

// Dump all non-Ram (const/rel) reference offsets with counts + a sample source addr.
public class DumpConstRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Map<Long,Integer> cnt = new HashMap<>();
        Map<Long,Address> sample = new HashMap<>();
        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            for (Reference r : prog.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                Address to = r.getToAddress();
                String sp = to.getAddressSpace().getName();
                if (sp.equals("Ram") || sp.equals("ram")) continue;
                long off = to.getOffset();
                cnt.merge(off, 1, Integer::sum);
                if (!sample.containsKey(off)) sample.put(off, ins.getAddress());
            }
        }
        for (Map.Entry<Long,Integer> e : cnt.entrySet()) {
            println("CREF 0x" + Long.toHexString(e.getKey()) + " n=" + e.getValue()
                + " src=" + sample.get(e.getKey()));
        }
        println("NCREF " + cnt.size());
        println("DONE");
    }
}
