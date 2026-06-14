import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class AnalyzeExportKey extends GhidraScript {
    public void run() throws Exception {
        var program = getCurrentProgram();
        var listing = program.getListing();
        var mem = program.getMemory();
        var fm = program.getFunctionManager();
        
        // 1. 找所有包含 "Export" 的函数
        println("=== Export-related Functions ===");
        for (var func : fm.getFunctions(true)) {
            var n = func.getName();
            if (n.toLowerCase().contains("export")) {
                println("Function: " + n + " at " + func.getEntryPoint() + " size=" + func.getBody().getNumAddresses());
            }
        }
        
        // 2. 找引用 "KspExportKey" 字符串的函数
        println("\n=== KspExportKey String Refs ===");
        var addr = findStringAddr("KspExportKey");
        if (addr != null) {
            println("String at: " + addr);
            var refs = getReferencesTo(addr);
            for (var ref : refs) {
                var func = getFunctionContaining(ref.getFromAddress());
                println("  Ref from: " + ref.getFromAddress() + " -> func: " + (func != null ? func.getName() : "null") + " at " + (func != null ? func.getEntryPoint().toString() : "?"));
                
                // Dump instructions of this function
                if (func != null) {
                    println("  --- Function disassembly ---");
                    var inst = listing.getInstructions(func.getEntryPoint(), true);
                    int count = 0;
                    while (inst.hasNext() && count < 100) {
                        var i = inst.next();
                        println("    " + i.getAddress() + ": " + i);
                        count++;
                    }
                }
            }
        }
        
        // 3. 找 "ClientExportKey" 字符串引用
        println("\n=== ClientExportKey String Refs ===");
        var addr2 = findStringAddr("ClientExportKey");
        if (addr2 != null) {
            var refs2 = getReferencesTo(addr2);
            for (var ref : refs2) {
                var func2 = getFunctionContaining(ref.getFromAddress());
                println("  Ref from: " + ref.getFromAddress() + " -> " + (func2 != null ? func2.getName() : "null"));
            }
        }
        
        // 4. 直接搜索 NTE_PERM (0x80090010) 常量引用
        println("\n=== Searching for NTE_PERM (0x80090010) ===");
        // This value indicates permission denied - export not allowed
        // Search in .text section
        var textBlock = mem.getBlock(".text");
        if (textBlock != null) {
            var bytes = new byte[4];
            var curAddr = textBlock.getStart();
            var endAddr = textBlock.getEnd();
            int found = 0;
            while (curAddr.compareTo(endAddr) < 0 && found < 20) {
                if (mem.getBytes(curAddr, bytes) == 4) {
                    // Check for mov eax, 0x80090010 or similar
                    int val = ((bytes[3] & 0xFF) << 24) | ((bytes[2] & 0xFF) << 16) | ((bytes[1] & 0xFF) << 8) | (bytes[0] & 0xFF);
                    if (val == 0x80090010) {
                        println("  NTE_PERM at: " + curAddr + " (file: 0x" + Long.toHexString(curAddr.getOffset()) + ")");
                        // Show surrounding instructions
                        var inst = listing.getInstructions(curAddr, true);
                        int c = 0;
                        while (inst.hasNext() && c < 5) { println("    " + inst.next()); c++; }
                        found++;
                    }
                }
                curAddr = curAddr.add(1);
            }
        }
    }
    
    ghidra.program.model.address.Address findStringAddr(String s) {
        var mem = getCurrentProgram().getMemory();
        var found = mem.findBytes(mem.getMinAddress(), s.getBytes(), null, true, monitor);
        return found;
    }
}
