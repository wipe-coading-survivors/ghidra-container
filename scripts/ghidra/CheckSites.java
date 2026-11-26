import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CheckSites extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Path p = Paths.get("/work/build/ghidra-sites.txt");
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
            Instruction ins = prog.getListing().getInstructionAt(a);
            Function fn = prog.getFunctionManager().getFunctionContaining(a);
            StringBuilder sb = new StringBuilder();
            sb.append("SITE ").append(a).append(" ").append(label).append(" | ");
            if (ins != null) {
                sb.append("INSTR=").append(ins.toString());
            } else {
                sb.append("INSTR=<none>");
            }
            sb.append(" | FN=");
            if (fn != null) {
                sb.append(fn.getEntryPoint()).append(" ").append(fn.getName());
            } else {
                sb.append("<none>");
            }
            int rc = 0;
            for (ReferenceIterator rit = prog.getReferenceManager().getReferencesTo(a);
                 rit.hasNext(); ) {
                if (rc >= 12) {
                    sb.append(" ...");
                    break;
                }
                Reference r = rit.next();
                sb.append(" [").append(r.getFromAddress()).append(":")
                  .append(r.getReferenceType().getName()).append("]");
                rc++;
            }
            sb.append(" | refsTo=").append(rc);
            println(sb.toString());
        }
        println("DONE");
    }
}
