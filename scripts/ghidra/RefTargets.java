import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

// One pass over all instructions; collect refs whose target is in [lo,hi)
// from /work/build/ghidra-range.txt. Prints each ref + a per-target summary.
public class RefTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Path p = Paths.get("/work/build/ghidra-range.txt");
        String[] t = Files.readString(p).trim().split("\\s+");
        long lo = Long.parseLong(t[0].replaceFirst("^0x", ""), 16);
        long hi = Long.parseLong(t[1].replaceFirst("^0x", ""), 16);
        Map<Long, Integer> targetCount = new HashMap<>();
        int n = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true);
             it.hasNext(); ) {
            Instruction ins = it.next();
            for (Reference r : prog.getReferenceManager()
                    .getReferencesFrom(ins.getAddress())) {
                long to = r.getToAddress().getOffset();
                if (to < lo || to >= hi) continue;
                targetCount.merge(to, 1, Integer::sum);
                if (n < 200) {
                    println("REF from=0x" + Long.toHexString(ins.getAddress().getOffset())
                        + " -> 0x" + Long.toHexString(to)
                        + " " + r.getReferenceType()
                        + " ins=" + ins.toString());
                    n++;
                }
            }
        }
        long distinct = targetCount.size();
        long total = targetCount.values().stream().mapToInt(Integer::intValue).sum();
        println("SUMMARY distinctTargets=" + distinct + " totalRefs=" + total
            + " range=[" + Long.toHexString(lo) + "," + Long.toHexString(hi) + ")");
        println("DONE");
    }
}
