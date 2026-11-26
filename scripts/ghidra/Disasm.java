import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class Disasm extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        Listing listing = prog.getListing();
        Memory memory = prog.getMemory();
        AddressSetView range = memory.getLoadedAndInitializedAddressSet();
        int total = 0;
        int unk = 0;
        int printed = 0;
        Address lo = null;
        Address hi = null;
        for (InstructionIterator it = listing.getInstructions(range, true); it.hasNext(); ) {
            Instruction ins = it.next();
            total++;
            if (lo == null) {
                lo = ins.getAddress();
            }
            hi = ins.getAddress();
            String s = ins.toString();
            if (s.startsWith("unk")) {
                unk++;
            }
            if (printed < 120) {
                println(ins.getAddress() + "  " + s);
                printed++;
            }
        }
        println("SUMMARY total=" + total + " unk=" + unk + " range=" + lo + "-" + hi);
        println("DONE");
    }
}
