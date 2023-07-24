from idaapi import * 
import idautils
import idc
import sys 

text_seg = idaapi.get_segm_by_name('.text')
vm_seg = idaapi.get_segm_by_name('.reloc') # extract

patch_junkcode = True
hide_junkcode = True
#edit_file = True

vm_total_count = 0
vm_start_ranges = []
vm_entry_ranges = []
vm_end_ranges = []

def format_address(address):
    new_address = str(address)
    if (str(address[-1:]) == 'L'):
        new_address = str(address[:-1])
    return new_address

def get_jump_destination(address):
    return idc.GetOperandValue(address, 0)

def get_mnemonic(address):
    return idc.GetMnem(address)

current_address = text_seg.startEA
print("looking for themida in range : " + format_address(hex(current_address)) + " to " + format_address(hex(text_seg.endEA)))
while(current_address <= text_seg.endEA):
    current_address = idc.FindBinary(current_address, SEARCH_DOWN, "E9")
    if idc.isCode(idc.GetFlags(current_address)):
            #print("current: ",hex(address))
            current_mnemonic = get_mnemonic(current_address)
            if current_mnemonic == "jmp":
                current_dest = get_jump_destination(current_address)
                if (current_dest >= vm_seg.startEA) and (current_dest <= vm_seg.endEA):
                    vm_start_address = current_address
                    vm_entry_address = current_dest
                    vm_end_address = idc.FindBinary(vm_start_address, SEARCH_DOWN, "89 ?? 89 ?? 89 ?? 89 ?? 89 ??")
                    vm_total_count += 1
                    ###############
                    if (patch_junkcode):
                        for junk_code in range(vm_start_address + 5, vm_end_address): 
                            PatchByte(junk_code, 0x90)
                    if (hide_junkcode):
                        HideArea(vm_start_address + 5, vm_end_address, "themida vm buffer junk", "vm_buffer_junk_start", "vm_buffer_junk_end", 0) 
                    '''
                    if (edit_file):
                        file_address= vm_start_address + 5 
                        new_value = 0x90
                        f = open(".exe", "rb+")
                        f.seek(file_address)
                        f.write(new_value)
                    '''
                    ###############
                    vm_start_ranges.append(format_address(hex(vm_start_address)))
                    vm_entry_ranges.append(format_address(hex(vm_entry_address)))
                    vm_end_ranges.append(format_address(hex(vm_end_address)))
                    print("--------> vm:\t" + format_address(hex(vm_start_address)) + "\n\tjump:\t" + format_address(hex(vm_entry_address)) + "\n\tend:\t" + format_address(hex(vm_end_address)))
    current_address += 1
# end while
print("total vms found: " + str(vm_total_count))

if (len(vm_start_ranges) == len(vm_entry_ranges) == len(vm_end_ranges)):
    print("balanced themida entries")
    f = open("vm_entries.json", "w+")
    entry_data = '{\n\t"count": ' + str(vm_total_count) 
    entry_data += ',\n\t"data": [\n'
    for x in range(len(vm_start_ranges)):
        entry_data += '\n\t\t{\n\t\t"start":"' + vm_start_ranges[x] + '",\n\t\t"entry":"' + vm_entry_ranges[x] + '",\n\t\t"end":"' + vm_end_ranges[x] + '"\n\t\t},'
    entry_data = entry_data[:-1]
    entry_data += '\n\t]\n}\n'
    f.write(entry_data)
    f.close()
else:
    print("unbalanced themida entries detected")
    print("no log")



'''
for address in idautils.Heads(text_seg.startEA, text_seg.endEA):

    if idc.isCode(idc.GetFlags(address)):
        print("current: ",hex(address))
        inst_mnemonic = get_mnemonic(address)
        if inst_mnemonic == "jmp":
            print("current found jmp: ", get_jump_destination(address))
'''
#if ()
    #tmp_sp_addr = idc.FindBinary(head_ea, SEARCH_DOWN, "89 ?? 89 ?? 89 ?? 89 ?? 89 ?? ")
    #if tmp_sp_addr == BADADDR:
    