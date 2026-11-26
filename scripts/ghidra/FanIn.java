import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class FanIn extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        ReferenceManager rm = prog.getReferenceManager();
        List<long[]> list = new ArrayList<long[]>();
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function fn = it.next();
            Address entry = fn.getEntryPoint();
            int in = 0, out = 0;
            for (Reference r : rm.getReferencesTo(entry)) {
                in++;
            }
            list.add(new long[]{entry.getOffset(), in,
                    fn.getBody().getMaxAddress().subtract(entry) + 1});
        }
        Collections.sort(list, Comparator.comparingLong(a -> -a[1]));
        int n = 0;
        for (long[] f : list) {
            if (n++ >= 30) break;
            println(String.format("FN 0x%06x in=%d size=%d", f[0], f[1], f[2]));
        }
        println("DONE");
    }
}
