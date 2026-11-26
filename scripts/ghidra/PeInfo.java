import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

public class PeInfo extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        println("IMAGE_BASE " + prog.getImageBase().getOffset());
        println("MIN " + prog.getMemory().getMinAddress()
            + " MAX " + prog.getMemory().getMaxAddress());
        int n = 0;
        for (FunctionIterator it = prog.getFunctionManager().getFunctions(true);
             it.hasNext(); ) {
            Function f = it.next();
            n++;
            println("FUNC " + f.getEntryPoint() + " " + f.getName() + " body=" + f.getBody().getNumAddresses());
        }
        println("FUNC_COUNT " + n);
        println("DONE");
    }
}
