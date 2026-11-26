import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DumpRange extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Address lo, hi;
        Path p = Paths.get("/work/build/ghidra-range.txt");
        if (Files.exists(p)) {
            String[] t = Files.readString(p).trim().split("\\s+");
            lo = af.getAddress(t[0]);
            hi = af.getAddress(t[1]);
        } else {
            AddressSetView all = prog.getMemory().getLoadedAndInitializedAddressSet();
            lo = all.getMinAddress();
            hi = all.getMaxAddress();
        }
        AddressSet range = af.getAddressSet(lo, hi);
        int fn = 0;
        java.util.Iterator<Function> fit =
                prog.getFunctionManager().getFunctionsOverlapping(range);
        while (fit.hasNext()) {
            Function f = fit.next();
            println("FUNC " + f.getEntryPoint() + " " + f.getName());
            fn++;
        }
        int n = 0, cap = 50000;
        for (InstructionIterator it = prog.getListing().getInstructions(range, true);
             it.hasNext() && n < cap; ) {
            Instruction ins = it.next();
            n++;
            println(ins.getAddress() + "  " + ins.toString());
        }
        int ref = 0;
        for (InstructionIterator it = prog.getListing().getInstructions(range, true);
             it.hasNext() && ref < cap; ) {
            Instruction ins = it.next();
            for (Reference r : prog.getReferenceManager()
                    .getReferencesFrom(ins.getAddress())) {
                println("REF " + ins.getAddress() + " -> " + r.getToAddress()
                        + " " + r.getReferenceType().getName());
                if (++ref >= cap) {
                    break;
                }
            }
        }
        println("SUMMARY range=" + lo + "-" + hi + " functions=" + fn
                + " ins=" + n + " refs=" + ref + " cap=" + cap);
        println("DONE");
    }
}
