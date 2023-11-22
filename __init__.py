# typedef int(*dmi_random_t)(int*, int);

from binaryninja import *

def create(bv):
    consts = set()
    for function in bv.functions:
        if function.medium_level_il is None:
            print(f"[-] No Medium Level IL for function at adddress {hex(function.start)}")
            continue
        for const in get_consts_from_function(bv, function):
            consts.add(const)
    with open(f"{bv.file.filename}.dict", "w") as f:
        print_dict_from(consts, bv.arch.address_size*4, f)
        print(f"[+] file {bv.file.filename}.dict written")

def get_consts_from_function(bv, func):
    consts = set()
    for basicblock in func.medium_level_il:
        for instruction in basicblock:
            if instruction.operation == MediumLevelILOperation.MLIL_IF:
                for operand in instruction.operands[0].operands:
                    try:
                        if operand.operation == MediumLevelILOperation.MLIL_CONST:
                            consts.add(operand.value.value)
                    except Exception as e:
                        continue
                        #print(e)
                        #print(instruction)
    return consts

def create_for_function(bv, func):
    consts = get_consts_from_function(bv, func)
    print_dict_from(consts, bv.arch.address_size*4,sys.stdout)

def print_dict_from(consts, bitsize=32,fd=sys.stdout):
    for idx, const in enumerate(consts):
        if bitsize == 16:
            print("kw{}=\"\\x{:>04x}\"".format(idx, const),file=fd)
        elif bitsize == 32:
            print("kw{}=\"\\x{:>08x}\"".format(idx, const),file=fd)
        elif bitsize == 64:
            print("kw{}=\"\\x{:>016x}\"".format(idx, const),file=fd)
        else:
            raise Exception("Unsupported bitsize: %d" % bitsize)

PluginCommand.register("Dictionary\\Create dictionary", "Attempt to create a fuzzing dictionary out of constants in the program", create)
PluginCommand.register_for_function("Dictionary\\Create dictionary for function", "Attempt to create a fuzzing dictionary out of constants for this function", create_for_function)
