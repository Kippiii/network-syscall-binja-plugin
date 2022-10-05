from typing import List

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction

class NotNetworkSyscallException(Exception):
    pass

class Syscall:
    num: int
    args: List[int]
    addr: int

    @classmethod
    def create(cls, inst: LowLevelILInstruction) -> "Syscall":
        return Syscall(inst.address)

    def __init__(self, addr: int):
        self.addr = addr

    def __str__(self) -> str:
        return "This is a comment"

    def add_comment(self, bv) -> None:
        bv.set_comment_at(self.addr, str(self))


class SocketSyscall(Syscall):
    domain: int
    type: int
    protocol: int


class BindSyscall(Syscall):
    sock_id: int
    sock_addr: int
    sock_addr_len: int


class ListenSyscall(Syscall):
    sock_id: int
    backlog: int


class AcceptSyscall(Syscall):
    sock_id: int
    sock_addr: int
    sock_addr_len: int


class ConnectSyscall(Syscall):
    sock_id: int
    sock_addr: int
    sock_addr_len: int


class SendSyscall(Syscall):
    sock_id: int
    buffer: int
    buffer_len: int
    flags: int
    dest_addr: int
    dest_addr_len: int


class RecvSyscall(Syscall):
    sock_id: int
    buffer: int
    buffer_len: int
    flags: int
    src_addr: int
    src_addr_len: int


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
            syscalls.append(Syscall.create(i))
        except NotNetworkSyscallException:
            pass
    return syscalls


def update_syscalls(bv):
    insts = get_syscall_instructions(bv)

    syscalls = gen_syscalls(insts)

    for syscall in syscalls:
        syscall.add_comment(bv)


PluginCommand.register("Network Syscalls", "Traces all network syscalls", update_syscalls)