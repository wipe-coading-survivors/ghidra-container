import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Lists every indirect CALL (via register or [reg+disp]) with the containing
// function. Output filtered later by service-table offsets (gRT/gBS/gST).
public class IndirectCalls extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Pattern bracket = Pattern.compile("\\[[^]]+\\]");
        int n = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true);
             it.hasNext(); ) {
            Instruction ins = it.next();
            String m = ins.getMnemonicString();
            if (!m.equals("CALL")) continue;
            String s = ins.toString();
            boolean mem = s.indexOf('[') >= 0;
            boolean reg = !mem && !s.contains("0x") && !s.startsWith("CALL qword ptr [");
            if (!mem && !reg) continue;
            if (mem) {
                Matcher mt = bracket.matcher(s);
                String operand = mt.find() ? mt.group() : "?";
                if (!operand.matches("\\[R[A-Z0-9]{2,3}( \\+ 0x[0-9a-f]+)?\\]")) continue;
            }
            Function fn = prog.getFunctionManager().getFunctionContaining(ins.getAddress());
            println("ICALL " + ins.getAddress() + " fn="
                + (fn == null ? "<none>" : "0x" + Long.toHexString(fn.getEntryPoint().getOffset()))
                + "  " + s);
            n++;
        }
        println("ICALL_COUNT " + n);
        println("DONE");
    }
}
