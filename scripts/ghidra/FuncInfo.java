import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

// Function count + the function containing 0x0 and 0x2083c (if any).
public class FuncInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        int n = 0;
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            it.next();
            n++;
        }
        println("COUNT " + n);
        for (long a : new long[]{0x0, 0x2083c, 0x565830}) {
            Address addr = af.getDefaultAddressSpace().getAddress(a);
            Function f = prog.getFunctionManager().getFunctionContaining(addr);
            println("AT 0x" + Long.toHexString(a) + " fn="
                + (f == null ? "<none>" : f.getName() + " @0x"
                    + Long.toHexString(f.getEntryPoint().getOffset())
                    + " body=" + f.getBody()));
        }
        println("DONE");
    }
}
