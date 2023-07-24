from idautils import *
from idaapi import *
from idc import *


print("[>] ez signature generator script\n\n\n")
text_seg = get_segm_by_name('.text')


G_MAX_OPCODE_SIZE   = 6
 
def add_bytes_to_signature(curSig, currentIns, size):
    for i in xrange(size):
        curSig = "%s%0.2X " % (curSig, idc.Byte(currentIns+i))
    return curSig
 
def add_whitespace_to_signature(curSig, size):
    for i in xrange(size):
        curSig = "%s? " % curSig;
    return curSig
 
def get_current_opcode_size(ea):
    inslen = idautils.DecodeInstruction(ea)
    for i in range(0, G_MAX_OPCODE_SIZE):
        if idaapi.cmd.Operands[i].type == o_void:
            return 0
        if idaapi.cmd.Operands[i].offb != 0:
            return idaapi.cmd.Operands[i].offb
    return 0
 
def match_operands(ea):
    if idaapi.get_first_dref_from(ea) != BADADDR:
        return False
    if idaapi.get_first_cref_from(ea) != BADADDR:
        return False
    return True
 
 
def add_instruction_to_signature(curSig, ea):
    uiSize = get_current_opcode_size(ea)
    size = ItemSize(ea)
    
    # If the instruction doesn't have any useful operand info, then just add the raw bytes
    if size < 5:
        curSig = add_bytes_to_signature(curSig, ea, size)
        return (curSig,size)
 
 
    if uiSize == 0:
        curSig = add_bytes_to_signature(curSig, ea, size)
    else:
        curSig = add_bytes_to_signature(curSig, ea, uiSize)
 
    if match_operands(ea):
        curSig = add_bytes_to_signature(curSig, ea + uiSize, size - uiSize)
    else:
        curSig = add_whitespace_to_signature(curSig, size - uiSize)
 
    return (curSig, size)
 
def is_signature_unique(pattern):
    if pattern == "":
        return False
    ea = FindBinary(0, SEARCH_DOWN, pattern)
    if ea == BADADDR:
        return True
    else:
        # Search again, starting 1 byte further so we can keep going until we get a unique pattern.
        if FindBinary(ea+1, SEARCH_DOWN, pattern) == BADADDR:
            return True
        else:
            return False

def get_signature(ea):
    curSig, len = add_instruction_to_signature("", ea)
    ea = ea+len
 
    while not is_signature_unique(curSig):
        curSig, len = add_instruction_to_signature(curSig, ea)
        ea = ea + len
 
    return curSig
  

def format_address(address):
    new_address = str(address)
    if (str(address[-1:]) == 'L'):
        new_address = str(address[:-1])
    return new_address

muh_code = []

for funcea in Functions(text_seg.startEA, text_seg.endEA):
    functionName = GetFunctionName(funcea)
    if (functionName.startswith("j_") is False) and \
        (functionName.startswith("sub_")is False) and \
        (functionName.startswith("SEH_")is False) and \
        (functionName.startswith("unknown_lib")is False) and \
        (functionName.startswith("null")is False):

        muh_code.append(dict({functionName: {
                                "address": format_address(hex(funcea)),
                                "signature": get_signature(funcea)
                                }
                            }))

# do whatever. save to file etc
for i in range(0, len(muh_code)):
    print(muh_code[i])


print("[*] total signatures created: " + str(len(muh_code)))
save_file = idaapi.get_root_filename() + ".signatures" + ".json"
print("[*] saving output in idb root folder with name: " + save_file)

f = open(save_file, "w+")
entry_data = '{\n\t"count": ' + str(len(muh_code))
entry_data += ',\n\t"data": [\n'
for x in range(len(muh_code)):
    entry_data += '\n\t\t{"' + str(muh_code[x].keys()[0]) + \
                  '" : {' + \
                  '"signature": "' + str(muh_code[x].values()[0]["signature"]) + '", ' + \
                  '"address": "' + str(muh_code[x].values()[0]["address"]) + '"' + \
                  '}},\n'
entry_data = entry_data[:-2]
entry_data += '\n\t]\n}\n'
f.write(entry_data)
f.close()

print("[>] signatures generated and saved - ez")