import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.HashMap;
import java.util.Map;

// Print first N examples of each load-family mnemonic with full text + refs.
public class LoadExamples extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        String[] want = {"ld.i", "lw.r", "lw.r.zx", "ld.d", "ld.w", "ld.b",
            "ld.q.17", "ld.d.17", "ld.q", "st.d", "st.w", "csr.r", "csr.w.0xb"};
        Map<String, Integer> shown = new HashMap<>();
        for (String w : want) shown.put(w, 0);
        int budget = 6;
        for (InstructionIterator it = prog.getListing().getInstructions(true);
             it.hasNext() && shown.values().stream().anyMatch(c -> c < budget); ) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString();
            Integer c = shown.get(m);
            if (c == null || c >= budget) continue;
            shown.put(m, c + 1);
            StringBuilder refs = new StringBuilder();
            for (ghidra.program.model.symbol.Reference r :
                    prog.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                refs.append(" ->0x").append(Long.toHexString(r.getToAddress().getOffset()))
                    .append(":").append(r.getReferenceType()).append(' ');
            }
            println("EX " + m + " @0x" + Long.toHexString(ins.getAddress().getOffset())
                + " : " + ins.toString() + (refs.length() > 0 ? "  [REF" + refs + "]" : "  [norefs]"));
        }
        println("DONE");
    }
}
