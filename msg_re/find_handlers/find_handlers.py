import os
import sys
import binaryninja as binja

if len(sys.argv) > 1:
    target = sys.argv[1]

    binja.log_to_stderr(True)

for filename in os.listdir(target):

    bv = binja.BinaryViewType.get_view_of_file(target + filename)
    if bv == None:
        continue;

    addHandler_addr = 0
    for func in bv.functions:
        name = func.name
        if func.name.startswith("_ZN") == True:
            type, name = binja.demangle.demangle_gnu3(binja.architecture.Architecture["x86"], func.name)
            name = binja.demangle.get_qualified_name(name)
            if name == "nv::Looper::addHandler":
                addHandler_addr = func.start

    if addHandler_addr == 0:
        continue

    addHandler_funcs = set()
    for xref in bv.get_code_refs(addHandler_addr):
        addHandler_funcs.add(bv.get_functions_containing(xref.address)[0])

    sys.stdout.write(filename)

    last_stored_constant = 0
    for func in addHandler_funcs:
        for block in func.medium_level_il:
            for instr in block:
                if instr.operation == binja.MediumLevelILOperation.MLIL_STORE and instr.src.operation == binja.MediumLevelILOperation.MLIL_CONST:
                    last_stored_constant = instr.src.constant
                if instr.operation == binja.MediumLevelILOperation.MLIL_CALL or instr.operation == binja.MediumLevelILOperation.MLIL_CALL_UNTYPED:
                    try:
                        if instr.dest.constant == addHandler_addr:
                            try:
                                handler = instr.params[1]
                                if instr.params[1].operation == binja.MediumLevelILOperation.MLIL_CONST:
                                    sys.stdout.write(',')
                                    sys.stdout.write(str(handler))
                            except:
                                handler = last_stored_constant
                                sys.stdout.write(',')
                                sys.stdout.write(str(handler))
                    except:
                        continue

    sys.stdout.write('\n')
    sys.stdout.flush()
