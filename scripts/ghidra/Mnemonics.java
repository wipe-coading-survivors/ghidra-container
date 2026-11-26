import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class Mnemonics extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Map<String, Integer> counts = new TreeMap<>();
        int total = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true);
             it.hasNext(); ) {
            Instruction ins = it.next();
            counts.merge(ins.getMnemonicString(), 1, Integer::sum);
            total++;
        }
        println("MNEMONICS total=" + total + " distinct=" + counts.size());
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            println(String.format("  %-24s %d", e.getKey(), e.getValue()));
        }
        println("DONE");
    }
}
