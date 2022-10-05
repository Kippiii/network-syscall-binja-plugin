from typing import List

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction

class NotNetworkSyscallException(Exception):
    pass

class Syscall:
    num: int
    args: List[int]

    def __init__(self, inst: LowLevelILInstruction):
        pass

    def __str__(self) -> str:
        pass

    def add_comment(self) -> None:
        pass


def get_syscall_instructions(bv) -> List[LowLevelILInstruction]:
    insts = []
    for function in bv.functions:
        for block in function.low_level_il:
            for i in block:
                if (i.operation == LowLevelILOperation.LLIL_SYSCALL):
                    insts.append(i)
    return insts


def gen_syscalls(insts: List[LowLevelILInstruction]) -> List[Syscall]:
    syscalls = []
    for i in insts:
        try:
            syscalls.append(Syscall(i))
        except NotNetworkSyscallException:
            pass
    return syscalls


def update_syscalls(bv):
    insts = get_syscall_instructions(bv)

    syscalls = gen_syscalls(insts)

    for syscall in syscalls:
        syscall.add_comment()


PluginCommand.register("Network Syscalls", "Traces all network syscalls", update_syscalls)