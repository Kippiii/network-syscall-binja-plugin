from typing import List, Tuple, Optional

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction, RegisterValue


class NotNetworkSyscallException(Exception):
    pass


def get_reg_value(inst: LowLevelILInstruction, reg_name: str, size: int = 8) -> Optional[int]:
    reg = inst.get_reg_value(reg_name)
    if reg.type == 0:
        return None
    if reg.type == 2:
        return reg.value
    if reg.type == 5:
        return inst.get_stack_contents(reg.value, size).value
    assert False, f"Given reg type of {reg.type} is unsupported here"


def parse_sockaddr(value: Optional[int]) -> Tuple[int, int, str]:
    if value is None:
        return -1, -1, ""
    family = value & 0xf
    port = (value & 0xffff0000) >> 16
    port = (port % 0x100 * 0x100) + (port // 0x100)
    ip = f"{(value & 0xff00000000) >> 32}.{(value & 0xff0000000000) >> 40}.{(value & 0xff000000000000) >> 56}.{(value & 0xff00000000000000) >> 72}"
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
            44: SendToSyscall,
            45: RecvFromSyscall,
        }
        sys_num = get_reg_value(inst, "rax")
        if sys_num not in syscall_map:
            raise NotNetworkSyscallException
        syscall = syscall_map[sys_num](inst)
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
    domain: Optional[int]
    type: Optional[int]
    protocol: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.domain = get_reg_value(inst, "rdi")
        self.type = get_reg_value(inst, "rsi")
        self.protocol = get_reg_value(inst, "rdx")

    def __str__(self) -> str:
        if self.protocol != 0 or self.type not in (1, 2):
            return "Created Socket of Unknown Type"
        network_proc = "TCP" if self.type == 1 else "UDP"
        return f"Created {network_proc} Socket"


class BindSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "rdx")
        if size is not None:
            value = get_reg_value(inst, "rsi", size)
        else:
            value = None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)

    def __str__(self) -> str:
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Bound to Port {port_str}"


class ListenSyscall(Syscall):
    backlog: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.backlog = get_reg_value(inst, "rsi", 4)

    def __str__(self) -> str:
        return f"Listening with Backlog={self.backlog if self.backlog is not None else 'Unknown'}"


class AcceptSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "rdx")
        value = get_reg_value(inst, "rsi", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)

    def __str__(self) -> str:
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Accepting on Port {port_str}"


class ConnectSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "rdx")
        value = get_reg_value(inst, "rsi", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)
    
    def __str__(self) -> str:
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Connecting on Port {port_str}"


class SendToSyscall(Syscall):
    family: int
    ip_addr: str
    port: int
    data: Optional[str]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        buffer_size = get_reg_value(inst, "rdx")
        buffer = get_reg_value(inst, "rsi", buffer_size) if buffer_size is not None else None
        size = get_reg_value(inst, "r9")
        value = get_reg_value(inst, "r8", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)
        self.data = ''.join([chr((buffer // (16**i)) % 16) for i in range(buffer_size)])[::-1] if buffer is not None else None
    
    def __str__(self) -> str:
        port_str = self.port if self.port != -1 else "Unknown"
        data_str = self.data if self.data is not None else "Unknown"
        return f"Sent '{data_str}' on Port {port_str}"


class RecvFromSyscall(Syscall):
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "r9")
        value = get_reg_value(inst, "r8", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)

    def __str__(self) -> str:
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Recieved Data on Port {port_str}"


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