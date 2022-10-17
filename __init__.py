from typing import List, Tuple, Optional

from binaryninja.plugin import PluginCommand
from binaryninja import LowLevelILOperation, LowLevelILInstruction, RegisterValue


class NotNetworkSyscallException(Exception):
    pass


def get_reg_value(inst: LowLevelILInstruction, reg_name: str, size: int = 8) -> Optional[int]:
    """
    Gets the value for a syscall parameter

    :param inst: The instruction where the syscall is made
    :param reg_name: The name of the register where parameter is stored
    :param size: The size of the parameter (only used when on stack)
    :return: The value of the parameter (or None if cannot be found)
    """
    reg = inst.get_reg_value(reg_name)
    if reg.type == 0:
        return None
    if reg.type == 2:
        return reg.value
    if reg.type == 5:
        return inst.get_stack_contents(reg.value, size).value
    assert False, f"Given reg type of {reg.type} is unsupported here"


def parse_sockaddr(value: Optional[int]) -> Tuple[int, int, str]:
    """
    Parses the sockaddr struct

    :param value: The value of the struct
    :return: A tuple of the family, port, and address
    """
    if value is None:
        return -1, -1, ""
    family = value & 0xf
    port = (value & 0xffff0000) >> 16
    port = (port % 0x100 * 0x100) + (port // 0x100)
    ip = f"{(value & 0xff00000000) >> 32}.{(value & 0xff0000000000) >> 40}.{(value & 0xff000000000000) >> 56}.{(value & 0xff00000000000000) >> 72}"
    return family, port, ip


class Syscall:
    """
    Stores a syscall object

    :param addr: The address where the syscall is made
    """
    addr: int

    @classmethod
    def create(cls, inst: LowLevelILInstruction) -> "Syscall":
        """
        Creates a syscall

        :param inst: The instruction of the syscall
        """
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

    def add_comment(self, bv) -> None:
        """
        Adds the comment for a syscall

        :param bv: The binary ninja object
        """
        bv.set_comment_at(self.addr, str(self))


class SocketSyscall(Syscall):
    """
    Represents an instance of the socket syscall

    :param domain: The domain used to create the socket
    :param type: The type used to create the socket
    :param protocol: The protocol used to create the socket
    """
    domain: Optional[int]
    type: Optional[int]
    protocol: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.domain = get_reg_value(inst, "rdi")
        self.type = get_reg_value(inst, "rsi")
        self.protocol = get_reg_value(inst, "rdx")

    def __str__(self) -> str:
        """
        Creates the string for the socket syscall

        :return: The string used for the comment
        """
        if self.protocol != 0 or self.type not in (1, 2):
            return "Created Socket of Unknown Type"
        network_proc = "TCP" if self.type == 1 else "UDP"
        return f"Created {network_proc} Socket"


class BindSyscall(Syscall):
    """
    Represents an instance of the bind syscall

    :param family: The family of the address
    :param ip_addr: The ip address bound to
    :param port: The port bound to
    """
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
        """
        Creates the string for the bind syscall

        :return: The string used for the comment
        """
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Bound to Port {port_str}"


class ListenSyscall(Syscall):
    """
    Represents an instance of the listen syscall

    :param backlog: The backlog for listening
    """
    backlog: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.backlog = get_reg_value(inst, "rsi", 4)

    def __str__(self) -> str:
        """
        Creates the string for the listen syscall

        :return: The string used for the comment
        """
        return f"Listening with Backlog={self.backlog if self.backlog is not None else 'Unknown'}"


class AcceptSyscall(Syscall):
    """
    Represents an instance of the accept syscall

    :param family: The family accepting on
    :param ip_addr: The ip address accepting on
    :param port: The port accepting on
    """
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "rdx")
        value = get_reg_value(inst, "rsi", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)

    def __str__(self) -> str:
        """
        Creates the string for the accept syscall

        :return: The string used for the comment
        """
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Accepting on Port {port_str}"


class ConnectSyscall(Syscall):
    """
    Represents an instance of the connect syscall

    :param family: The family connecting on
    :param ip_addr: The ip connecting to
    :param port: The port connecting to
    """
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "rdx")
        value = get_reg_value(inst, "rsi", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)
    
    def __str__(self) -> str:
        """
        Creates the string for the connect syscall

        :return: The string used for the comment
        """
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Connecting on Port {port_str}"


class SendToSyscall(Syscall):
    """
    Represents an instance of the sendto syscall

    :param family: The family being sent on
    :param ip_addr: The ip address being sent to
    :param port: The port being sent to
    :param data: The data being sent
    """
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
        """
        Creates the string for the sendto syscall

        :return: The string used for the comment
        """
        port_str = self.port if self.port != -1 else "Unknown"
        data_str = self.data if self.data is not None else "Unknown"
        return f"Sent '{data_str}' on Port {port_str}"


class RecvFromSyscall(Syscall):
    """
    Represents an instance of the recvfrom syscall

    :param family: The family being used for recieving
    :param ip_addr: The ip address being recieved from
    :param port: The port being recieved from
    """
    family: int
    ip_addr: str
    port: int

    def __init__(self, inst: LowLevelILInstruction) -> None:
        size = get_reg_value(inst, "r9")
        value = get_reg_value(inst, "r8", size) if size is not None else None
        self.family, self.port, self.ip_addr = parse_sockaddr(value)

    def __str__(self) -> str:
        """
        Creates the string for the recvfrom syscall

        :return: The string used for the comment
        """
        port_str = self.port if self.port != -1 else "Unknown"
        return f"Recieved Data on Port {port_str}"

class SendMsgSyscall(Syscall):
    """
    Represents an instance of the sendmsg syscall

    :param struct: The value of the user_msghdr struct
    """
    struct: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.struct = get_reg_value(inst, "rsi", 56)

    def __str__(self) -> str:
        """
        Creates the string for the sendmsg syscall

        :return: The string used for the comment
        """
        struct_str = hex(self.struct) if self.struct is not None else "Unknown"
        return f"Sent Data with Msg Struct of {struct_str}"

class RecvMsgSyscall(Syscall):
    """
    Representsan instance of the recvmsg syscall

    :param struct: The value of the user_msghdr struct
    """
    struct: Optional[int]

    def __init__(self, inst: LowLevelILInstruction) -> None:
        self.struct = get_reg_value(inst, "rsi", 56)
    
    def __str__(self) -> str:
        """
        Creates the string for the recvmsg syscall

        :return: The string used for the comment
        """
        struct_str = hex(self.struct) if self.struct is not None else "Unknown"
        return f"Recieved Data with Msg Struct of {struct_str}"


def get_syscall_instructions(bv) -> List[LowLevelILInstruction]:
    """
    Gets a list of instruction where syscalls occur

    :param bv: The binary ninja object
    :return: The list of instructions
    """
    insts = []
    for function in bv.functions:
        for block in function.low_level_il:
            for i in block:
                if (i.operation == LowLevelILOperation.LLIL_SYSCALL):
                    insts.append(i)
    return insts


def gen_syscalls(insts: List[LowLevelILInstruction]) -> List[Syscall]:
    """
    Generates syscalls objects at all instructions

    :param insts: The instructions where syscalls occur
    :return: A list of syscall objects
    """
    syscalls = []
    for i in insts:
        try:
            syscalls.append(Syscall.create(i))
        except NotNetworkSyscallException:
            pass
    return syscalls


def update_syscalls(bv):
    """
    Adds comments to a program at all the network syscall instructions

    :param bv: The binary ninja object
    """
    insts = get_syscall_instructions(bv)

    syscalls = gen_syscalls(insts)

    for syscall in syscalls:
        syscall.add_comment(bv)


PluginCommand.register("Network Syscalls", "Traces all network syscalls", update_syscalls)