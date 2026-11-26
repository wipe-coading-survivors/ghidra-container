import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

// List functions overlapping any [lo,hi) range from /work/build/ghidra-ranges8b.txt (one "0xlo 0xhi" per line).
public class FuncsInRanges extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Path p = Paths.get("/work/build/ghidra-ranges8b.txt");
        List<long[]> ranges = new ArrayList<>();
        for (String line : Files.readAllLines(p)) {
            line = line.trim();
            if (line.isEmpty()) continue;
            String[] t = line.split("\\s+");
            ranges.add(new long[]{Long.parseLong(t[0].replaceFirst("^0x", ""), 16),
                                  Long.parseLong(t[1].replaceFirst("^0x", ""), 16)});
        }
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true); it.hasNext(); ) {
            Function f = it.next();
            long s = f.getBody().getMinAddress().getOffset();
            long x = f.getBody().getMaxAddress().getOffset();
            for (long[] r : ranges) {
                if (x < r[0] || s >= r[1]) continue;
                println(String.format("fn@0x%x body=[0x%x,0x%x] len=0x%x",
                    f.getEntryPoint().getOffset(), s, x, x - s + 1));
                break;
            }
        }
        println("DONE");
    }
}
