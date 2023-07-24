from idautils import *
from idaapi import *
from idc import *
import json
import sys


print("[>] ez signature namer script\n\n\n")
text_seg = idaapi.get_segm_by_name('.text')


load_file = idaapi.get_root_filename() + ".signatures" + ".json"
signature_data = json.load(open(load_file))
print("signatures loaded: " + load_file)

signature_list = []

for key in signature_data["data"]:
    print(key)
    signature_list.append(key)

def fix_hex(string):
    return string.replace('0x', '')

def format_address(address):
    new_address = str(address)
    if (str(address[-1:]) == 'L'):
        new_address = str(address[:-1])
    return new_address

def is_signature_unique(pattern):
    if pattern == "":
        return False
    ea = FindBinary(text_seg.startEA, SEARCH_DOWN, pattern)
    if ea == BADADDR:
        return True
    else:
        # Search again, starting 1 byte further so we can keep going until we get a unique pattern.
        if FindBinary(ea+1, SEARCH_DOWN, pattern) == BADADDR:
            return True
        else:
            return False

sig_applied = 0
for i in range(0, len(signature_list)):
    function_name = str(signature_list[i].keys()[0])
    function_signature = str(signature_list[i].values()[0]["signature"])
    function_address = str(signature_list[i].values()[0]["address"])
    first_found_address = idc.FindBinary(text_seg.startEA, SEARCH_DOWN, function_signature)
    if is_signature_unique(function_signature) and first_found_address <= text_seg.endEA:
        if GetFunctionName(first_found_address) != function_name:
            print("[*] updating " + format_address(hex(first_found_address)) + " with '" + function_name + "'")
            idc.MakeNameEx(first_found_address, function_name, idc.SN_CHECK)
            sig_applied += 1
        else:
            print("[!] " + function_name + "' already named at " + format_address(hex(first_found_address)))
    else:
        print("[!] '" + function_name + '" does not have a unique signature or is unable to search for the signature properly "' + function_signature + '"')


print("[>] applied " + str(sig_applied) + "/" + str(len(signature_data["data"])) + " signatures - ez")
