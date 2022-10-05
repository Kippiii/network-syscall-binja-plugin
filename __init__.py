from binaryninja.plugin import PluginCommand

def update_syscalls(bv):
    pass

PluginCommand.register("Network Syscalls", "Traces all network syscalls", update_syscalls)