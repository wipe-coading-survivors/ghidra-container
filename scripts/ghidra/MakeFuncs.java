import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Paths;

// Creates a function at each address (hex per line) of
// /work/build/ghidra-scan.txt (instructions must already exist).
public class MakeFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        for (String line : Files.readAllLines(Paths.get("/work/build/ghidra-scan.txt"))) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            long t = Long.parseLong(line.replaceFirst("^0x", ""), 16);
            Address a = af.getDefaultAddressSpace().getAddress(t);
            Function old = prog.getFunctionManager().getFunctionAt(a);
            if (old != null) {
                println("MAKE exists 0x" + Long.toHexString(t) + " " + old.getName());
                continue;
            }
            Function f = createFunction(a, "sub_" + Long.toHexString(t));
            println("MAKE 0x" + Long.toHexString(t) + " -> "
                + (f == null ? "FAILED" : f.getName() + " body=" + f.getBody().getNumAddresses()));
        }
        println("DONE");
    }
}
