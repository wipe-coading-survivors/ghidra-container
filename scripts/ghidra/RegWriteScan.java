import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import java.util.LinkedHashMap;
import java.util.Map;

// Scan all instructions for register-file write/read mechanism evidence.
// (1) ld.i / st.i : last operand = word index; RAM byte addr = index*4. Flag index 0x8fc (RAM 0x23f0).
// (2) st.d/st.w/st.b/st.q (+ '!') and ld.d/ld.w/ld.b/ld.q : operands rt, base, off (absolute RAM).
//     If base is a known zero reg (zero/zerol/r30/r30l) the target RAM addr == off; flag if in RF range.
// (3) csr.r / csr.w* : regspace 0x40000+X; flag if text references 0x23f0/0x423f0.
// (4) Dump boot window around 0x1d598 (detour).
public class RegWriteScan extends GhidraScript {
    static final long UNLOCK_WORD = 0x8fc;
    static final long UNLOCK_RAM  = 0x23f0;
    static final long RF_LO = 0x0, RF_HI = 0x40000;

    long parseImm(String s) {
        s = s.trim();
        boolean neg = s.startsWith("-");
        if (neg) s = s.substring(1);
        long v;
        if (s.startsWith("0x") || s.startsWith("0X")) v = Long.parseLong(s.substring(2), 16);
        else v = Long.parseLong(s, 10);
        return neg ? -v : v;
    }

    String[] operands(String s) {
        int sp = s.indexOf(' ');
        if (sp < 0) return new String[0];
        String ops = s.substring(sp + 1).trim();
        return ops.split(",\\s*");
    }

    boolean isZeroBase(String r) {
        r = r.toLowerCase();
        return r.equals("zero") || r.equals("zerol") || r.equals("r30") || r.equals("r30l");
    }

    @Override
    public void run() throws Exception {
        Program prog = getCurrentProgram();
        int nLdi = 0, nSti = 0, nStAbs = 0, nLdAbs = 0, nCsr = 0, nUnlock = 0;
        Map<Long,Integer> stiTargets = new LinkedHashMap<>();
        Map<Long,Integer> rfStores = new LinkedHashMap<>();

        for (InstructionIterator it = prog.getListing().getInstructions(true); it.hasNext(); ) {
            Instruction ins = it.next();
            long off = ins.getAddress().getOffset();
            String m = ins.getMnemonicString();
            String s = ins.toString();
            String[] op = operands(s);

            if (m.equals("ld.i") || m.equals("st.i")) {
                if (op.length < 2) continue;
                long idx = parseImm(op[op.length - 1]);
                long ram = idx * 4;
                if (m.equals("st.i")) { nSti++; stiTargets.merge(ram, 1, Integer::sum); }
                else nLdi++;
                if (idx == UNLOCK_WORD) {
                    nUnlock++;
                    println("UNLOCK " + s + " @0x" + Long.toHexString(off)
                        + " idx=0x" + Long.toHexString(idx) + " ram=0x" + Long.toHexString(ram));
                }
                continue;
            }

            boolean isStoreAbs = m.startsWith("st.d") || m.startsWith("st.w")
                || m.startsWith("st.b") || m.startsWith("st.q");
            boolean isLoadAbs  = m.startsWith("ld.d") || m.startsWith("ld.w")
                || m.startsWith("ld.b") || m.startsWith("ld.q");
            if ((isStoreAbs || isLoadAbs) && op.length >= 3) {
                String base = op[1];
                long offv = parseImm(op[2]);
                if (isStoreAbs) nStAbs++; else nLdAbs++;
                if (isZeroBase(base)) {
                    long resolved = offv & 0xffffffffL;
                    if (resolved >= RF_LO && resolved < RF_HI) {
                        if (isStoreAbs) rfStores.merge(resolved, 1, Integer::sum);
                        if (rfStores.size() <= 500)
                            println((isStoreAbs ? "RFSTORE " : "RFLOAD  ") + s
                                + " @0x" + Long.toHexString(off)
                                + " base=" + base + " off=0x" + Long.toHexString(offv & 0xffffffffL)
                                + " ->ram=0x" + Long.toHexString(resolved)
                                + (resolved == UNLOCK_RAM ? "  <<< UNLOCK" : ""));
                    }
                }
                continue;
            }

            if (m.startsWith("csr.r") || m.startsWith("csr.w")) {
                nCsr++;
                boolean isUnlock = s.contains("0x23f0") || s.contains("0x423f0");
                if (isUnlock || (m.startsWith("csr.w") && nCsr <= 40)) {
                    println("CSR " + s + " @0x" + Long.toHexString(off)
                        + (isUnlock ? "  <<< UNLOCK" : ""));
                }
                continue;
            }
        }
        println("SUMMARY ld.i=" + nLdi + " st.i=" + nSti + " stAbs=" + nStAbs
            + " ldAbs=" + nLdAbs + " csr=" + nCsr + " unlockHits=" + nUnlock);
        println("=== st.i target histogram (ram addr -> count), top 40 ===");
        stiTargets.entrySet().stream()
            .sorted((a,b) -> Integer.compare(b.getValue(), a.getValue()))
            .limit(40)
            .forEach(e -> println(String.format("  st.i ->ram=0x%s x%d%s",
                Long.toHexString(e.getKey()), e.getValue(),
                e.getKey()==UNLOCK_RAM ? "  <<< UNLOCK" : "")));
        println("=== RF-range absolute STORES via zero-base, distinct ram addrs (all) ===");
        rfStores.entrySet().stream()
            .sorted((a,b) -> Long.compare(a.getKey(), b.getKey()))
            .forEach(e -> println(String.format("  ->ram=0x%s x%d%s",
                Long.toHexString(e.getKey()), e.getValue(),
                e.getKey()==UNLOCK_RAM ? "  <<< UNLOCK" : "")));

        Address base0 = prog.getImageBase();
        Address start = base0.add(0x1d598L - 0x20);
        Address stop  = base0.add(0x1d598L + 0x40);
        println("=== boot window 0x1d578..0x1d5d8 (detour @0x1d598) ===");
        for (InstructionIterator it = prog.getListing().getInstructions(new AddressSet(start, stop), true);
             it.hasNext(); ) {
            Instruction i = it.next();
            println("  " + Long.toHexString(i.getAddress().getOffset()) + "  " + i.toString());
        }
        println("DONE");
    }
}
