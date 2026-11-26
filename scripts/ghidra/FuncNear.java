import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

// List functions whose body overlaps [lo,hi) from /work/build/ghidra-range.txt.
public class FuncNear extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Path p = Paths.get("/work/build/ghidra-range.txt");
        String[] t = Files.readString(p).trim().split("\\s+");
        long lo = Long.parseLong(t[0].replaceFirst("^0x", ""), 16);
        long hi = Long.parseLong(t[1].replaceFirst("^0x", ""), 16);
        int n = 0;
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function f = it.next();
            long s = f.getBody().getMinAddress().getOffset();
            long x = f.getBody().getMaxAddress().getOffset();
            if (x < lo || s >= hi) continue;
            n++;
            println(String.format("  fn@0x%x body=[0x%x,0x%x] len=0x%x",
                f.getEntryPoint().getOffset(), s, x, x - s + 1));
        }
        println("FUNCNEAR n=" + n + " range=[0x" + Long.toHexString(lo)
            + ",0x" + Long.toHexString(hi) + ")");
        println("DONE");
    }
}
