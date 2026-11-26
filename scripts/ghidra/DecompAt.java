import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;

// Decompiles every distinct function containing one of the addresses listed
// (hex per line) in /work/build/ghidra-scan.txt.
public class DecompAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Set<Long> addrs = new LinkedHashSet<>();
        for (String line : Files.readAllLines(Paths.get("/work/build/ghidra-scan.txt"))) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("0x") || line.startsWith("0X")) line = line.substring(2);
            addrs.add(Long.parseLong(line, 16));
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(prog);
        Set<Long> done = new LinkedHashSet<>();
        for (long t : addrs) {
            Address a = af.getDefaultAddressSpace().getAddress(t);
            Function fn = prog.getFunctionManager().getFunctionContaining(a);
            if (fn == null) {
                println("==== addr 0x" + Long.toHexString(t) + " NO-FUNCTION");
                continue;
            }
            long ep = fn.getEntryPoint().getOffset();
            if (!done.add(ep)) {
                println("==== addr 0x" + Long.toHexString(t)
                    + " dup of fn @0x" + Long.toHexString(ep));
                continue;
            }
            DecompileResults res = di.decompileFunction(fn, 120, monitor);
            println("==== addr 0x" + Long.toHexString(t) + " fn @0x"
                + Long.toHexString(ep) + " size=" + fn.getBody().getNumAddresses()
                + " ok=" + res.decompileCompleted()
                + " err=" + res.getErrorMessage());
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("// decompile failed: " + res.getErrorMessage());
            }
        }
        di.dispose();
        println("DONE");
    }
}
