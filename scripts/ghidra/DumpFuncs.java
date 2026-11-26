import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DumpFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Path p = Paths.get("/work/build/ghidra-funcs.txt");
        if (!Files.exists(p)) {
            println("ERROR no " + p);
            println("DONE");
            return;
        }
        for (String line : Files.readAllLines(p)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] t = line.split("\\s+");
            Address a = af.getAddress(t[0]);
            String label = t.length > 1 ? t[1] : "";
            Function fn = prog.getFunctionManager().getFunctionContaining(a);
            if (fn == null) {
                println("SITE " + a + " " + label + " | FN=<none>");
                continue;
            }
            Address fe = fn.getEntryPoint();
            Address ff = fn.getBody().getMaxAddress();
            long size = ff.subtract(fe) + 1;
            println("FUNC " + fe + " " + fn.getName()
                    + " size=" + size + " (site " + a + " " + label + ")");
            int n = 0, cap = 20000;
            for (InstructionIterator it =
                     prog.getListing().getInstructions(fn.getBody(), true);
                 it.hasNext() && n < cap; ) {
                Instruction ins = it.next();
                n++;
                String mark = ins.getAddress().equals(a) ? ">>" : "  ";
                println(mark + " " + ins.getAddress() + "  " + ins.toString());
            }
            int ref = 0;
            for (InstructionIterator it =
                     prog.getListing().getInstructions(fn.getBody(), true);
                 it.hasNext() && ref < cap; ) {
                Instruction ins = it.next();
                for (Reference r : prog.getReferenceManager()
                        .getReferencesFrom(ins.getAddress())) {
                    println("   REF " + ins.getAddress() + " -> "
                            + r.getToAddress() + " "
                            + r.getReferenceType().getName());
                    ref++;
                }
            }
        }
        println("DONE");
    }
}
