import idaapi
import idc

mnemonic_jump_unconditional = ['jmp']

def get_mnemonic(address):
    """obtain mnemonic from address"""
    try:
        return idc.GetMnem(address)
    except ValueError:
        idc.Warning("<!> ERROR - Not able to get mnemonic in get_mnemonic(address)")
        return str(idc.BADADDR)

def get_operand(address, position=0):
    """obtain operand value at 'n' position from address"""
    try:
        return idc.GetOperandValue(address, position)
    except ValueError:
        idc.Warning("<!> ERROR - Not able to get operand in get_operand(address, position)")




def is_jump_chain(address):
    """checks if the address leads to a jump chain. declared if more than one jump"""
    jump_count = 0
    while get_mnemonic(address) in mnemonic_jump_unconditional:
        address += 1
        jump_count += 1
        address = get_operand(address)
    if jump_count > 1:
        return True
    return False


print("done")


print(is_jump_chain(0x00C25500))
