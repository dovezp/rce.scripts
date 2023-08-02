
import os
import sys
import subprocess

lines = None
with open(sys.argv[1], 'r') as f:
    lines = f.read().splitlines()

block_filter = ("call", "jmp", "jp", "jo", "jno", "js", "jns", "je", "jz", "jne", "jnz", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja", "jnbe", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz")

raw_address = []
addresses = []
assembly = []
index = 0
switch = False
for line in lines:
    #print(line)
    trace_segments = line.split()
    #print(trace_segments)
    lined = ""
    for segment in trace_segments:
        if segment.endswith(":"):
            raw_address.append(segment.replace(":", ""))
        if not (segment.endswith(":") or segment == ";"):
            lined = lined + " " + segment
            if (segment.startswith(block_filter)):
                switch = True
            if (switch and not segment.startswith(block_filter)):
                test = ""
                if (segment.find("loc_") != -1):
                    test = segment.replace('loc_','')
                if (segment.find("sub_") != -1):
                    test = segment.replace('sub_','')
                if (segment.find("$+5") != -1):
                    test = "0x" + raw_address[index]
                    hex_int = int(test, 16)
                    new_int = hex_int + 0x5
                    test = "" + hex(new_int)[2:]
                addresses.append(test.upper())
                switch = False

        else:
            assembly.append(lined)
    index = index + 1
    #assembly.append(segements[1])

z = []
yyy = 0
switch2 = False
for x in lines:
    #print(line)
    trace_segments = x.split()
    xxxx = ""
    for segment in trace_segments:
        if (segment.endswith(":")):
            if (segment[:-1] in addresses)and (test in raw_address):
                xxxx = xxxx + "chunk_" + segment[:-1] + ":\n"
        elif not (segment.endswith(":") or segment == ";"):
            if (segment.startswith(block_filter)):
                switch2 = True
            if (switch2 and not segment.startswith(block_filter)):
                test = ""
                if (segment.find("loc_") != -1):
                    test = segment.replace('loc_','')
                if (segment.find("sub_") != -1):
                    test = segment.replace('sub_','')
                if (segment.find("$+5") != -1):
                    test = "0x" + raw_address[yyy]
                    hex_int = int(test, 16)
                    new_int = hex_int + 0x5
                    test = "" + hex(new_int)[2:]
                if (test in addresses) and (test in raw_address):
                    xxxx = xxxx + " chunk_" + test
                else:
                    xxxx = xxxx + " unknown"
                switch2 = False
            else:
                xxxx = xxxx + " " + segment
        else:
            z.append(xxxx)
    yyy = yyy + 1

formated_assembly = []
for line in z:
    if line.strip() != "":
        #print(line)
        formated_assembly.append(line.strip())

#for x,y in addresses:
#    print(x + " -- " + y)
'''
formated_assembly = []
for line in assembly:
    if line.strip() != "":
        #print(line)
        formated_assembly.append(line.strip())
# filter out ["call", "jnz", "jz","jne", "je", "jmp", "jp"]
'''
log_count = 0

nasm_header = "section .text\n"\
            "global _start\n"\
            "_start:\n"
nasm_footer = "\nunknown:\nint 80h"

#block_return = "retn" 
block_log = nasm_header
for block in formated_assembly:
    if (block.find("dword ptr") != -1):
        test = block.replace('dword ptr','dword ')
        #print(test)
        block_log = block_log + test + "\n"
    elif (block.find("var_") != -1):
        test = block[:block.find("var_") + 5] + 'h' + block[block.find("var_") + 5:]
        #y = block.find("var")  + 5
        #block = block[block.find("var") + 4 "h"
        #print(block[block.find("var") + 4] + block[y])
        test = test.replace('var_','')
        #print(test)
        block_log = block_log + test + "\n"
    else:
        block_log = block_log + block + "\n"
block_log = block_log + nasm_footer
print(block_log)
f = open("blocks/" + "test-block.asm", "w")
f.write(block_log)
f.close()
block_log = ""


subprocess.call("build.bat")
exit()
#subprocess.call(["cmd","FOR %%c in (blocks\*.asm) DO nasm -f win32 %%c -o blocks\%%~nc.exe"])
