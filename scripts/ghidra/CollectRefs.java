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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

// Collects every reference in the program. For each, checks:
//  (a) ram-space target is a target address; or
//  (b) non-ram (const/rel) space target, when added to a candidate base,
//      lands on a target address. Reports matches with the function.
public class CollectRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        AddressFactory af = prog.getAddressFactory();
        Path p = Paths.get("/work/build/ghidra-sites.txt");
        if (!Files.exists(p)) { println("ERROR no " + p); println("DONE"); return; }
        Set<Long> targets = new HashSet<>();
        Map<Long,String> tname = new HashMap<>();
        for (String line : Files.readAllLines(p)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] t = line.split("\\s+");
            String hs = t[0].startsWith("0x") || t[0].startsWith("0X") ? t[0].substring(2) : t[0];
            long a = Long.parseUnsignedLong(hs, 16);
            targets.add(a);
            tname.put(a, t.length>1?t[1]:"?");
        }
        long[] bases = {0x3b0000L, 0x3c0000L};
        int nram=0, nconst=0, nhit=0;
        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            for (Reference r : prog.getReferenceManager().getReferencesFrom(ins.getAddress())) {
                Address to = r.getToAddress();
                long toOff = to.getOffset();
                String sp = to.getAddressSpace().getName();
                if (sp.equals("Ram") || sp.equals("ram")) {
                    nram++;
                    if (targets.contains(toOff)) {
                        Function fn = prog.getFunctionManager().getFunctionContaining(ins.getAddress());
                        String fns = (fn==null)?"<none>":(fn.getEntryPoint()+" "+fn.getName());
                        println("HIT-RAM  " + ins.getAddress() + " -> " + to + " ["+r.getReferenceType().getName()+"] fn=" + fns + " target=" + tname.get(toOff));
                        nhit++;
                    }
                } else {
                    nconst++;
                    for (long base : bases) {
                        long cand = base + toOff;
                        // also try signed interpretation of a 32-bit offset
                        long cand32 = base + (toOff & 0xffffffffL) - ((toOff>>31)&0xffffffffL);
                        for (long c : new long[]{cand, cand32}) {
                            if (targets.contains(c)) {
                                Function fn = prog.getFunctionManager().getFunctionContaining(ins.getAddress());
                                String fns = (fn==null)?"<none>":(fn.getEntryPoint()+" "+fn.getName());
                                println("HIT-CONST base=0x" + Long.toHexString(base) + "  " + ins.getAddress()
                                    + " -> space=" + sp + " off=0x" + Long.toHexString(toOff)
                                    + " => 0x" + Long.toHexString(c) + " ["+r.getReferenceType().getName()+"] fn=" + fns
                                    + " target=" + tname.get(c));
                                nhit++;
                            }
                        }
                    }
                }
            }
        }
        println("SUMMARY ram_refs=" + nram + " nonram_refs=" + nconst + " hits=" + nhit);
        println("DONE");
    }
}
