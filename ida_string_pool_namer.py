import idaapi
import idautils
import idc

'''
68 ? ? ? ? 50 E8 ? ? ? ? 8B C8 E8 ? ? ? ?
68 ? ? ? ? 51 E8 ? ? ? ? 8B C8 E8 ? ? ? ?
68 ? ? ? ? 52 E8 ? ? ? ? 8B C8 E8 ? ? ? ?

1st call ?GetInstance@StringPool@@SAAAV1@XZ

2nd call ?GetBSTR@StringPool@@QAE?AVZtl_bstr_t@@I@Z


D6 DE 75 86 46 64 A3 71 E8 E6 7B D3 33 30 E7 2E

?ms_aKey@StringPool@@0QBEB


E8 ? ? ? ? 6A 04 B9 ? ? ? ? C6

1st call ?GetString@StringPool@@AAE?AV?$ZXString@D@@ID@Z


8B 87 ? ? ? ? B9 ? ? ? ? 6A 04 0F BE 00 89 45 EC E8

1st mov ?ms_aString@StringPool@@0PAPBDA
2nd mov ?_s_alloc@?$ZAllocEx@VZAllocAnonSelector@@@@0V1@A
'''

START_ADDR = 0x00400000

# # #
#   Gets the starting address of a function if it can be found with the provided AoB
def get_aob_func_addr(aob):
    addr = idc.find_binary(START_ADDR, SEARCH_DOWN, str(aob)) # str() is integral here
    
    if addr == BADADDR:
        return addr
        
    return get_func_attr(addr, FUNCATTR_START)

# # #
#   Gets the nth function starting address when xrefing the given function
def GetNthFuncXref(addr, num):
    xrefAddr = GetNthXref(addr, num)
    
    if xrefAddr == BADADDR:
        return BADADDR

    return get_func_attr(xrefAddr, FUNCATTR_START)

def GetNthXref(addr, num):
    xrefRet = BADADDR
    
    count = 0
    
    if len(list(XrefsTo(addr, 0))) <= 0: # need to cast to list before getting len cuz its a generator not iterator
        return BADADDR
    
    for xref in XrefsTo(addr, 0):
        count += 1
        
        if count < num:
            continue
            
        xrefRet = xref.frm
        break
    
    return xrefRet

# renames the 
def RenameFunction(addr, name):
    demangledFuncName = Demangle(name, GetShortPrm(INF_SHORT_DN))
    
    result = "Invalid address supplied."   
    
    if MakeName(get_func_attr(addr, FUNCATTR_START), str(name)) > 0:
        result = "Found and renamed function."

    print "[RenameFunction] [{}] [{}] {}".format(demangledFuncName, hex(addr)[:-1], result)

# renames the first function call
def RenameFirstCallInFunc(addr, name):
    demangledFuncName = Demangle(name, GetShortPrm(INF_SHORT_DN))
    
    result = "Invalid address supplied."   
    
    if addr != BADADDR:
        if len(list(FuncItems(addr))) <= 0: # need to cast to list to get length because FuncItems is a generator not an iterator
            result = "Unable to find any instructions."
        else:
            result = ""
        
            for instruction in FuncItems(addr):
                if GetMnem(instruction) == "call":
                    addr = get_operand_value(instruction, 0)
                    MakeName(addr, str(name))
                    result = "Found and renamed first function call."
                    break
            
            if len(result) <= 0:
                result = "Unable to find any call instructions."

    print "[RenameFirstCall] [{}] [{}] {}".format(demangledFuncName, hex(addr)[:-1], result)

# renames the preceding call of the given address
def RenamePreviousCall(addr, name):
    demangledFuncName = Demangle(name, GetShortPrm(INF_SHORT_DN))
    
    result = "Invalid address supplied."
    
    if addr != BADADDR:
        funcInstructions = list(FuncItems(addr))
        if len(funcInstructions) <= 0:
            result = "Unable to find any instructions."
        else:
            result = ""
            
            for instruction in reversed(funcInstructions):
                if instruction >= addr:
                    continue
                
                if GetMnem(instruction) == "call":
                    addr = get_operand_value(instruction, 0)
                    MakeName(addr, str(name))
                    result = "Found and renamed previous call."
                    break
            
            if len(result) <= 0:
                result = "Unable to find previous call instruction."
        
    print "[RenamePreviousCall] [{}] [{}] {}".format(demangledFuncName, hex(addr)[:-1], result)

# aobs work in GMS v95 and v176, backup methods have been implemented for v83 (might work in other versions)
AOB_STRINGPOOL = "C7 04 81 00 00 00 00 40 EB ? 8B C6 8B 4C 24 ? 64 89 0D 00 00 00 00 59 5F 5E"
AOB_STRINGPOOL_GETKEY = "8B 71 FC 8B 44 24 08 33 D2 F7 F6 5E 8A 04 0A C2 04 00"
AOB_GETBSTR = "A1 ? ? ? ? 33 C4 50 8D 44 24 ? 64 A3 00 00 00 00 C7 44 24 ? 00 00 00 00 8B 44 24 ? 50 8D 54 24 ? 52 E8 ? ? ? ? 8B 00"

# Function Attribute Flags: FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER, FUNCATTR_REFQTY


# StringPool::Decode()

addr_StringPool_GetKey = get_aob_func_addr(AOB_STRINGPOOL_GETKEY) # StringPool::Key::GetKey

RenameFunction(addr_StringPool_GetKey, "?GetKey@Key@StringPool@@QBEEI@Z")

addr_DecodeStringPool = GetNthFuncXref(addr_StringPool_GetKey, 1) # `anonymous namespace'::Decode

if addr_DecodeStringPool == BADADDR:
    print "Issue with xrefing StringPool::Key::GetKey(), using backup method to generate StringPool::Decode"
    
    AOB_DECODE = "30 ? 75 02 88 ? ? ? 80 ? ? 75 ? " # at some point between v95 and v176 they merged the GetKey func into the Decode func
    addr_DecodeStringPool = get_aob_func_addr(AOB_DECODE)
    
    if addr_DecodeStringPool == BADADDR:
        print "Unable to generate StringPool::Decode using backup method. Dependent functions will not be named."
    
# Funcs Dependent On StringPool::Decode()

addr_GetStringBase = GetNthFuncXref(addr_DecodeStringPool, 1) # GetString func used to find the GetString we want
addr_GetStringWBase = GetNthFuncXref(addr_GetStringBase, 2) # GetStringW func used to find the GetStringW we want

RenameFunction(addr_DecodeStringPool, "??$Decode@D@?A0x61af31b1@@YAXAAV?$ZXString@D@@PBEII@Z")
RenameFunction(addr_GetStringBase, "?GetString@StringPool@@AAE?AV?$ZXString@D@@ID@Z")
RenameFunction(addr_GetStringWBase, "?GetString@StringPool@@AAE?AV?$ZXString@G@@IG@Z")
print

addr_GetString = GetNthFuncXref(addr_GetStringBase, 1) # the real GetString() func address
addr_GetStringW = GetNthFuncXref(addr_GetStringWBase, 1) # the real GetStringW() func address

RenameFunction(addr_GetString, "?GetString@StringPool@@QAE?AV?$ZXString@D@@I@Z")
RenameFunction(addr_GetStringW, "?GetStringW@StringPool@@QAE?AV?$ZXString@G@@I@Z")
print

# StringPool::GetBSTR()

addr_GetBSTR = get_aob_func_addr(AOB_GETBSTR)

if addr_GetBSTR == BADADDR:
    print "StringPool::GetBSTR() AOB failed to generate results, attempting backup method."
    
    addr_GetBSTR = GetNthXref(addr_GetString, 1)
    
    if addr_GetBSTR != BADADDR:
        RenameFunction(addr_GetBSTR, "?GetBSTR@StringPool@@QAE?AVZtl_bstr_t@@I@Z")
    else:
        print "Unable to find StringPool::GetBSTR() with the provided information."
else:
    RenameFunction(addr_GetBSTR, "?GetBSTR@StringPool@@QAE?AVZtl_bstr_t@@I@Z")

print

# StringPool::GetInstance()

addr_StringPool = get_aob_func_addr(AOB_STRINGPOOL)

if addr_StringPool == BADADDR: # aob breaks somewhere between v83 and v95
    print "StringPool::GetInstance() AOB failed to generate results, attempting backup method."
    
    firstXref = GetNthXref(addr_GetStringW, 1)

    if firstXref != BADADDR:
        RenamePreviousCall(firstXref, "?GetInstance@StringPool@@SAAAV1@XZ")
    else:
        print "Unable to find StringPool::GetInstance() with the provided information."
    
else: # for v95 and v176
    RenameFunction(addr_StringPool, "??0StringPool@@AAE@XZ")
    addr_StringPoolInstance = GetNthXref(addr_StringPool, 1)
    RenameFunction(addr_StringPoolInstance, "?GetInstance@StringPool@@SAAAV1@XZ")











