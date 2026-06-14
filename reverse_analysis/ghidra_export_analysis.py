#@category FaceWinUnlock
# Analyze KSP ExportKey function

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import RefType

program = getCurrentProgram()
listing = program.getListing()
mem = program.getMemory()

# Find KspExportKey string
addr = mem.findBytes(mem.getMinAddress(), "KspExportKey".getBytes(), None, True, getMonitor())
if addr:
    print("KspExportKey at {}".format(addr))
    refs = getReferencesTo(addr)
    for ref in refs:
        func = getFunctionContaining(ref.getFromAddress())
        if func:
            print("  Ref in function: {} at {}".format(func.getName(), func.getEntryPoint()))
            # Print first 30 instructions of this function
            instr = listing.getInstructions(func.getEntryPoint(), True)
            count = 0
            while instr.hasNext() and count < 80:
                inst = instr.next()
                print("    {}: {}".format(inst.getAddress(), inst))
                count += 1

# Find ClientExportKey string  
addr2 = mem.findBytes(mem.getMinAddress(), "ClientExportKey".getBytes(), None, True, getMonitor())
if addr2:
    print("ClientExportKey at {}".format(addr2))
    refs2 = getReferencesTo(addr2)
    for ref in refs2:
        func2 = getFunctionContaining(ref.getFromAddress())
        if func2:
            print("  Ref in: {} at {}".format(func2.getName(), func2.getEntryPoint()))
            instr = listing.getInstructions(func2.getEntryPoint(), True)
            count = 0
            while instr.hasNext() and count < 80:
                inst = instr.next()
                print("    {}: {}".format(inst.getAddress(), inst))
                count += 1

# List all functions containing "Export" or "export"
fm = program.getFunctionManager()
for func in fm.getFunctions(True):
    name = func.getName()
    if "Export" in name or "export" in name:
        print("Function: {} at {}".format(name, func.getEntryPoint()))
