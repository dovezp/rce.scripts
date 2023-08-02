from idaapi import * 
import idautils
import idc
import json
import sys 

jump_byte = 0xE9
jump_mnemonic = 'jmp'


vm_seg = idaapi.get_segm_by_name('.extract')


def fix_hex(string):
    return string.replace('0x', '')

def format_address(address):
    new_address = str(address)
    if (str(address[-1:]) == 'L'):
        new_address = str(address[:-1])
    return new_address

def get_jump_destination(address):
    return idc.GetOperandValue(address, 0)

def get_mnemonic(address):
    return idc.GetMnem(address)


test_entry = 0x03A6E32C #0x036A9556 #0x039E4DF8
end_entry = 0

x = 1
current_address = test_entry
while (get_mnemonic(current_address) == jump_mnemonic):
    x +=1
    current_address = get_jump_destination(current_address)
    print("end jump step in chain " + format_address(hex(current_address)))

print("jumps taken " + str(x))
print("vm end return result start " + format_address(hex(current_address)))

# always point to same one ending location

# ends:
# 3b7984f
# 
