import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class TopFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        List<long[]> list = new ArrayList<long[]>();
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function fn = it.next();
            long size = fn.getBody().getMaxAddress()
                    .subtract(fn.getEntryPoint()) + 1;
            list.add(new long[]{fn.getEntryPoint().getOffset(), size});
        }
        Collections.sort(list, Comparator.comparingLong(a -> -a[1]));
        int n = 0;
        for (long[] f : list) {
            if (n++ >= 40) break;
            println(String.format("FUNC 0x%06x size=%d", f[0], f[1]));
        }
        println("DONE");
    }
}
