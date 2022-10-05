from typing import List

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction

class Syscall:
    num: int
    args: List[int]
    def __init__(self, inst):
        pass

def get_syscall_instructions(bv) -> List[LowLevelILInstruction]:
    insts = []
    for function in bv.functions:
        for block in function.low_level_il:
            for i in block:
                if (i.operation == LowLevelILOperation.LLIL_SYSCALL):
                    insts.append(i)
    return insts

def update_syscalls(bv):
    pass

PluginCommand.register("Network Syscalls", "Traces all network syscalls", update_syscalls)