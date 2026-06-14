# Ghidra script: extract cryptngc.dll function list and BCrypt/NCrypt call sites
# Run as: analyzeHeadless <project> <project_name> -process cryptngc.dll -postScript ghidra_extract.py

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import SimpleBlockModel, CodeBlock
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp
import jarray

monitor = ConsoleTaskMonitor()

# ────────────────────────────────────────────────────────────
# 1. List all functions
# ────────────────────────────────────────────────────────────
print("=" * 80)
print("ALL FUNCTIONS IN cryptngc.dll")
print("=" * 80)

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)

for func in functions:
    body = func.getBody()
    name = func.getName()
    addr = func.getEntryPoint()
    size = body.getNumAddresses()
    # count instructions
    code_units = []
    code_manager = currentProgram.getCodeManager()
    cu = code_manager.getCodeUnitAt(addr)
    if cu:
        print(f"0x{addr.toString(False):>16}  {name}")

# ────────────────────────────────────────────────────────────
# 2. Find functions that reference BCrypt*/NCrypt* imports
# ────────────────────────────────────────────────────────────
print()
print("=" * 80)
print("FUNCTIONS CALLING BCrypt or NCrypt APIs")
print("=" * 80)

# Get the external manager
ext_mgr = currentProgram.getExternalManager()
ext_list = ext_mgr.getExternalLibraries()
crypto_libs = []

for lib in ext_list:
    lib_name = lib.getName().lower()
    if 'bcrypt' in lib_name or 'ncrypt' in lib_name:
        crypto_libs.append(lib)
        print(f"\nLibrary: {lib.getName()}")

# For each external function in bcrypt/ncrypt
for lib in crypto_libs:
    for ext_func in lib.getExternalFunctions():
        func_name = ext_func.getName()
        ext_addr = ext_func.getExternalLocationAddress()

        # Find all references to this external function
        ref_mgr = currentProgram.getReferenceManager()
        refs = ref_mgr.getReferencesTo(ext_addr)

        callers = set()
        for ref in refs:
            if ref.getReferenceType().isCall():
                caller_addr = ref.getFromAddress()
                caller_func = fm.getFunctionContaining(caller_addr)
                if caller_func:
                    callers.add(caller_func.getName())

        if callers:
            print(f"\n  {func_name} @ {ext_addr.toString(False)}")
            for caller in sorted(callers):
                print(f"    <- {caller}")

# ────────────────────────────────────────────────────────────
# 3. Decompile key functions and search for crypto calls
# ────────────────────────────────────────────────────────────
print()
print("=" * 80)
print("DECOMPILING KEY FUNCTIONS")
print("=" * 80)

# Initialize decompiler
iface = DecompInterface()
iface.setOptions(DecompileOptions())
iface.openProgram(currentProgram)

key_func_names = [
    "NgcDecryptWithUserIdKey",
    "NgcDecryptWithUserIdKeySilent",
    "NgcCreateUserIdKey",
    "NgcCreateUserIdKeyEx",
    "NgcCreateUserIdKeyHandle",
    "NgcSignWithUserIdKey",
    "NgcSignWithUserIdKeySilent",
    "NgcChangePin",
    "NgcChangePinSilent",
    "NgcCreateContainer",
    "NgcOpenUserIdKey",
    "FUN_1800197F0",  # NgcCreateUserIdKeyHandle alternate
]

for func in functions:
    name = func.getName()
    for kn in key_func_names:
        if kn in name or name in kn:
            print(f"\n--- {name} @ {func.getEntryPoint()} ---")
            res = iface.decompileFunction(func, 30, monitor)
            if res and res.getHighFunction():
                hf = res.getHighFunction()
                pcode = hf.getPcodeOps()
                while pcode.hasNext():
                    op = pcode.next()
                    mnem = op.getOpcode()
                    # Check for CALL operations
                    if mnem == PcodeOp.CALL:
                        inputs = op.getInputs()
                        if inputs and len(inputs) > 0:
                            target = inputs[0]
                            print(f"  CALL: {op}")
                    elif mnem == PcodeOp.CALLIND:
                        print(f"  CALLIND: {op}")
            break

print()
print("ANALYSIS COMPLETE")
