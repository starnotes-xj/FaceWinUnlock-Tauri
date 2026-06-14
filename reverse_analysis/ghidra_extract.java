// Ghidra script: extract cryptngc.dll function list and BCrypt/NCrypt references
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.TaskMonitor;

public class ghidra_extract extends GhidraScript {

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        ExternalManager extMgr = currentProgram.getExternalManager();

        // ─── 1. List all functions ───────────────────────────
        println("=" + repeat("=", 78) + "=");
        println("ALL FUNCTIONS IN cryptngc.dll");
        println("=" + repeat("=", 78) + "=");

        FunctionIterator funcs = fm.getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (!f.isThunk()) {
                println(f.getEntryPoint().toString(false) + "  " + f.getName());
                count++;
            }
        }
        println("\nTotal non-thunk functions: " + count);

        // ─── 2. Find BCrypt* / NCrypt* external functions and their callers ──
        println("\n" + "=" + repeat("=", 78) + "=");
        println("BCRYPT/NCRYPT IMPORT CALL SITES");
        println("=" + repeat("=", 78) + "=");

        for (ExternalLocation extLoc : extMgr.getExternalLocations()) {
            String libName = extLoc.getLibraryName();
            String funcName = extLoc.getFunctionName();
            if (funcName == null) continue;
            if (!libName.toLowerCase().contains("bcrypt") &&
                !libName.toLowerCase().contains("ncrypt")) continue;

            Address extAddr = extLoc.getExternalSpaceAddress();
            if (extAddr == null) continue;

            ReferenceIterator refs = refMgr.getReferencesTo(extAddr);
            boolean hasRefs = false;
            while (refs.hasNext()) {
                Reference ref = refs.next();
                if (ref.getReferenceType().isCall()) {
                    if (!hasRefs) {
                        println("\n" + funcName + " [" + libName + "] @ " + extAddr);
                        hasRefs = true;
                    }
                    Address fromAddr = ref.getFromAddress();
                    Function caller = fm.getFunctionContaining(fromAddr);
                    if (caller != null) {
                        println("    CALL <- " + caller.getName() + " @ " + caller.getEntryPoint());
                    } else {
                        println("    CALL <- " + fromAddr + " (no function)");
                    }
                }
            }
        }

        // ─── 3. Decompile key functions ──────────────────────
        println("\n" + "=" + repeat("=", 78) + "=");
        println("DECOMPILED BCrypt/NCrypt CALLS IN KEY FUNCTIONS");
        println("=" + repeat("=", 78) + "=");

        DecompInterface decomp = new DecompInterface();
        decomp.setOptions(new DecompileOptions());
        decomp.openProgram(currentProgram);

        String[] keyFuncs = {
            "NgcDecryptWithUserIdKey", "NgcDecryptWithUserIdKeySilent",
            "NgcCreateUserIdKey", "NgcCreateUserIdKeyEx", "NgcCreateUserIdKeyHandle",
            "NgcSignWithUserIdKey", "NgcSignWithUserIdKeySilent",
            "NgcChangePin", "NgcChangePinSilent",
            "NgcCreateContainer", "NgcCreateContainerSilent",
            "NgcOpenUserIdKey", "NgcGetUserIdKeyName",
            "NgcPackAuthBuffer", "NgcUnpackAuthBuffer",
            "NgcEncryptWithAsymmetricKey", "FidoCreateCredential"
        };

        funcs = fm.getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            String fname = func.getName();

            // Check if this is a key function
            boolean isKey = false;
            for (String kf : keyFuncs) {
                if (fname.contains(kf) || kf.contains(fname)) {
                    isKey = true;
                    break;
                }
            }
            if (!isKey) continue;

            println("\n--- " + fname + " @ " + func.getEntryPoint() + " ---");

            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res == null || !res.decompileCompleted()) {
                println("  Decompile failed: " + res.getErrorMessage());
                continue;
            }

            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                println("  No high function");
                continue;
            }

            // Walk pcode to find CALL operations
            Iterator<PcodeOpAST> pcodeIter = hf.getPcodeOps();
            while (pcodeIter.hasNext()) {
                PcodeOpAST op = pcodeIter.next();
                int opcode = op.getOpcode();

                if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                    Varnode[] inputs = op.getInputs();
                    if (inputs != null && inputs.length > 0) {
                        Varnode target = inputs[0];
                        Address targetAddr = target.getAddress();
                        Symbol sym = getSymbolAt(targetAddr);
                        if (sym != null) {
                            String symName = sym.getName();
                            if (symName.contains("BCrypt") || symName.contains("NCrypt") ||
                                symName.contains("CryptProtect") || symName.contains("CryptUnprotect") ||
                                symName.contains("RpcBinding") || symName.contains("NdrClientCall")) {
                                println("    " + op.toString());
                            }
                        }
                    }
                }
            }
        }

        println("\n" + "ANALYSIS COMPLETE");
    }

    private String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
