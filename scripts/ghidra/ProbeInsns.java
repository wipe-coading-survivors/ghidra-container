import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.regex.Pattern;

public class ProbeInsns extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        int n = 0;
        Pattern p = Pattern.compile("(?i)(?<![0-9a-f])1d56(?![0-9a-f])");
        int matched = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            n++;
            String s = ins.toString();
            if (n <= 10) println("SAMPLE " + ins.getAddress() + " | [" + s + "]");
            if (p.matcher(s).find()) matched++;
        }
        println("TOTAL " + n + " matched1d56=" + matched);
        Instruction at = prog.getListing().getInstructionAt(prog.getAddressFactory().getAddress("0x3098"));
        println("AT3098 " + (at == null ? "<none>" : at.toString()));
        println("DONE");
    }
}
