from typing import List, Tuple

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction, RegisterValue


class NotNetworkSyscallException(Exception):
    pass


def parse_sockaddr(value: int) -> Tuple[int, int, str]:
    family = value & 0xf
    port = (value & 0xff00) >> 8
    ip = f"{(value & 0xff0000) >> 16}.{(value & 0xff000000) >> 24}.{(value & 0xff00000000) >> 32}.{(value & 0xff0000000000) >> 40}"
    return family, port, ip


class Syscall:
    name: str
    args: List[int]
    addr: int

    @classmethod
    def create(cls, inst: LowLevelILInstruction) -> "Syscall":
        syscall_map = {
            41: SocketSyscall,
            49: BindSyscall,
            50: ListenSyscall,
            43: AcceptSyscall,
            42: ConnectSyscall,
            46: SendSyscall,
            47: RecvSyscall,
        }
        sys_num = inst.get_reg_value("rax").value
        if sys_num not in syscall_map:
            raise NotNetworkSyscallException
        regs = ["rdi", "rsi", "edx", "r10", "r8", "r9"]
        args = [inst.get_reg_value(reg) for reg in regs]
        syscall = syscall_map[sys_num](args)
        syscall.addr = inst.address
        return syscall

    def __init__(self):
        pass

    def __str__(self) -> str:
        params = ", ".join(map(str, self.args))
        return f"{self.name}({params})"

    def add_comment(self, bv) -> None:
        bv.set_comment_at(self.addr, str(self))


class SocketSyscall(Syscall):
    domain: int
    type: int
    protocol: int

    def __init__(self, args: List[RegisterValue]) -> None:
        self.domain = args[0].value
        self.type = args[1].value
        self.protocol = args[2].value

    def __str__(self) -> str:
        return f"socket({self.domain}, {self.type}, {self.protocol})"


class BindSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, args: List[RegisterValue]) -> None:
        self.family, self.port, self.ip_addr = parse_sockaddr(args[1].value)

    def __str__(self) -> str:
        return f"bind({self.family}, {self.port}, {self.ip_addr})"


class ListenSyscall(Syscall):
    backlog: int

    def __init__(self, args: List[RegisterValue]) -> None:
        self.backlog = args[1].value

    def __str__(self) -> str:
        return f"listen({self.backlog})"


class AcceptSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, args: List[RegisterValue]) -> None:
        self.family, self.port, self.ip_addr = parse_sockaddr(args[1].value)

    def __str__(self) -> str:
        return f"accept({self.family}, {self.port}, {self.ip_addr})"


class ConnectSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, args: List[RegisterValue]) -> None:
        self.family, self.port, self.ip_addr = parse_sockaddr(args[1].value)
    
    def __str__(self) -> str:
        return f"connect({self.family}, {self.port}, {self.ip_addr})"


class SendSyscall(Syscall):
    ip_addr: str
    port: int
    data: str
    flags: int

    def __init__(self, args: List[RegisterValue]) -> None:
        pass
    
    def __str__(self) -> str:
        return "send syscall has not been configured"


class RecvSyscall(Syscall):
    ip_addr: str
    port: int
    data: str
    flags: int

    def __init__(self, args: List[RegisterValue]) -> None:
        pass

    def __str__(self) -> str:
        return "recv syscall has not been configured"


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