import array
import idc
import idaapi
import idautils
from time import localtime, strftime
import time

# Constants
MAX_STR_LEN = 2048
SCRIPT_SEGMENT_NAME = ".string" # [m]aple [s]tory [s]tring [p]ool [d]ata
SCRIPT_SEGMENT_SIZE = 1048576  # 1 MiB
USE_EXP_DECOMP_COMMENT = False

# Maplestory stringpool stuff
# Doesn't seem to change throughout versions
ms_aKey = bytearray([0xD6, 0xDE, 0x75, 0x86, 0x46, 0x64, 0xA3, 0x71, 0xE8, 0xE6, 0x7B, 0xD3, 0x33, 0x30, 0xE7, 0x2E])
ms_nKeySize = 0x10

# These are gotten by AOB scans.
ms_nSize = BADADDR
ms_aString = BADADDR

def FATAL():
    print("[!] Exiting.")
    exit(1)

def ba_to_hex_str(ba):
    return ' '.join(format(n,'02X') for n in ba)

def ida_c_strlen(ea):
    return (idaapi.find_byte(ea, MAX_STR_LEN, 0, 1) - ea)

def update_ms_aString():
    # Get the stringpool by an AOB search.
    tmp_sp_addr = idc.FindBinary(0, SEARCH_DOWN, "8B 87 ? ? ? ? B9 ? ? ? ? 6A 04 0F BE 00 89 45 EC E8") # 53 6F 72 72 79 2C 20 74 68 69 73 20 69 73 6E 27 74 20 61 20 62 61 63 6B 75 70 2E 20 4A 75 73 74 20 70 72 6F 6F 66 20 56 6B 69 6B 6F 32 20 6D 61 64 65 20 74 68 69 73 2E
    if tmp_sp_addr == BADADDR:
        print("[!] Error locating string pool by AOB!")
        print("[!] Find the function in the executable and update the script.")
        FATAL()

    # Get the ms_aString address
    global ms_aString
    ms_aString = idaapi.get_long(tmp_sp_addr + 0x2)
    if ms_aString == BADADDR:
        print("[!] Error reading the ms_aString address!")
        FATAL()

def update_ms_nSize():
    # Temporarily get the ms_aKey address to offset against by AOB search.
    tmp_ms_aKey = idc.FindBinary(0, SEARCH_DOWN, "D6 DE 75 86 46 64 A3 71 E8 E6 7B D3 33 30 E7 2E")
    if tmp_ms_aKey == BADADDR:
        print("[!] Error locating the ms_aKey to offset against for ms_nSize!")
        print("[!] Update or hard-fix get_ms_nSize() in the script.")
        FATAL()

    # Get the ms_aString address
    global ms_nSize
    ms_nSize = idaapi.get_long(tmp_ms_aKey+0x14)
    if ms_nSize == BADADDR:
        print("[!] Error reading the ms_nSize address!")
        FATAL()

def get_string_pool_calls():
    aobs = ["68 ? ? ? ? 50 E8 ? ? ? ? 8B C8 E8 ? ? ? ?", "68 ? ? ? ? 51 E8 ? ? ? ? 8B C8 E8 ? ? ? ?", "68 ? ? ? ? 52 E8 ? ? ? ? 8B C8 E8 ? ? ? ?"]
    addrs = []
    for aob in aobs:
        addr = 0
        while addr != BADADDR:
            addr = idc.FindBinary(addr+1, SEARCH_NEXT|SEARCH_DOWN, aob)
            if addr != BADADDR:
                addrs.append(addr)

    calls = {}
    for addr in addrs:
        sp_idx = idaapi.get_long(addr+1)
        if sp_idx > ms_nSize+1:
            continue
        call_inst_addr = addr+13
        calls.setdefault(sp_idx, [])
        calls[sp_idx].append(call_inst_addr)
    return calls

def rotatel(arr, size, shift):
    newArr = bytearray()
    newArr[:] = arr
    if shift == 0 or size == 0:
        return newArr
    if shift >= 0:
        for i in range(0, size):
            newArr[i] = arr[((shift >> 3) % size + i) % size]
    if (shift & 7) != 0:
        shift = shift & 7
        b0 = newArr[0]
        for i in range(0, size):
            a = 0
            if i != (size-1):
                a = (newArr[i+1] >> 8 - shift) & 0xFF
            newArr[i] = (a | (newArr[i] << shift)) & 0xFF
        newArr[size-1] = newArr[size-1] | (b0 >> 8 - shift) & 0xFF
    return newArr

def decode_string(enc_arr, shift):
    new_key = rotatel(ms_aKey, ms_nKeySize, shift)
    out_arr = array.array('B')

    for i in range(0, len(enc_arr)):
        c_key = new_key[i % ms_nKeySize]
        if c_key != enc_arr[i]:
            c_key = c_key ^ enc_arr[i]
        out_arr.append(c_key)
    return out_arr.tostring().decode("latin_1")

def get_string_at_idx(idx):
    enc_str_addr = idaapi.get_long(ms_aString + 4*idx)
    shift = idaapi.get_byte(enc_str_addr)
    str_len = ida_c_strlen(enc_str_addr+1)
    if str_len == 0:
        return ""
    enc_data = idc.GetManyBytes(enc_str_addr+1, str_len)

    # Copy-Convert to bytearray :/
    dc = bytearray()
    dc[:] = enc_data

    return decode_string(dc, shift)

# Based on "append_segment" from
# https://github.com/fireeye/flare-ida/blob/master/python/flare/IDB_MSDN_Annotator/__init__.py
def make_new_segment():
    # Get last segment EA
    last_seg_ea = 0
    for s in idautils.Segments():
        if idc.SegEnd(s) > last_seg_ea:
            last_seg_ea = idc.SegEnd(s)

    # Sanity check
    if last_seg_ea == 0:
        print("[!] Something has gone HORRIBLY wrong,")
        print("    the only way this could possibly happen")
        print("    is if the idb had NO segments at all.")
        FATAL()

    # Check if segment already exists
    for s in idautils.Segments():
        if idc.SegName(s) == SCRIPT_SEGMENT_NAME:
            print("[!] The {} segment already exists!")
            print("[!] Have you already run this script?")
            FATAL()

    new_seg_ea = last_seg_ea
    if not idc.AddSeg(new_seg_ea, new_seg_ea+SCRIPT_SEGMENT_SIZE, 0, 1, 0, idaapi.scPub) == 1:
        print("[!] Error adding segment.")
        FATAL()
    if not idc.RenameSeg(new_seg_ea, SCRIPT_SEGMENT_NAME):
        print("[!] Error renaming segment.")
        FATAL()
    if not idc.SetSegClass(new_seg_ea, 'DATA'):
        print("[!] Error setting segment class.")
        FATAL()
    if not idc.SegAlign(new_seg_ea, idc.saRelPara):
        print("[!] Error aligning segment.")
        FATAL()
    if not idc.SetSegAddressing(new_seg_ea, 1):
        print("[!] Error setting segment addressing mode.")
        FATAL()
    return new_seg_ea

def write_segment_strings(seg_start_ea, strs):
    seg_strings_dict = {}
    cur_ea = seg_start_ea
    for i in range(0, len(strs)):
        str_to_write = u"{}\x00".format(strs[i]).encode("utf8")
        slen = len(str_to_write)
        idaapi.patch_many_bytes(cur_ea, str_to_write)
        idc.MakeStr(cur_ea, BADADDR)

        seg_strings_dict[i] = cur_ea

        cur_ea += slen
    return seg_strings_dict


def generate_ida_comments(cmt_list, rpt=False):
    """
    Generate idapython script to make comments, optionally repeatable.
    Parameters:
      cmt_list : list that contains virtual addresses and comment strings
    Returns: IDA Python script to make comments
    """
    ida_cmt_str = 'import idc\n\n'
    ida_cmt_str += 'def append_comment(ea, cmt):\n'
    ida_cmt_str += '    current_cmt = CommentEx(ea, %d)\n' % int(rpt)
    ida_cmt_str += '    if current_cmt:\n'
    ida_cmt_str += '        cmt = "%s\\n%s\\n" % (current_cmt, cmt)\n'
    ida_cmt_str += '    idc.%s(ea, cmt)\n\n' % (("MakeRptCmt" if rpt else "MakeComm"))

    for ea, cmt in cmt_list:
        ida_cmt_str += 'append_comment(0x%x, %s)\n' % (ea, str(escape(cmt)))
        ida_cmt_str += 'print hex(0x%x), %s\n' % (ea, str(escape(cmt)))

    return str(ida_cmt_str)


def try_make_comment(ea, comment):
    # Assembly comment
    MakeComm(ea, comment)

    # Decompiler comment
    if USE_EXP_DECOMP_COMMENT:
        try:
            fstart = idc.GetFunctionAttr(ea, FUNCATTR_START)
            if fstart == BADADDR:
                return
            cfunc = idaapi.decompile(fstart)
            tl = idaapi.treeloc_t()
            tl.ea = ea
            tl.itp = idaapi.ITP_SEMI
            cfunc.set_user_cmt(tl, comment)
            cfunc.save_user_cmts()
        except Exception, e:
            print("[-] Exception on trying to make decompiler comment: {}".format(e))

def main():
    choice = AskYN(0, "This script could easily destory or corrupt your database, make a backup before contining.\nAre you sure you wish to run the script?")
    if choice != 1:
        print("[!] Exiting by user choice!")
        return

    print("\n[+] ==== Maplestory String Pool Decryptor started ====")
    print("[+] Current time {}".format(strftime("%I:%M:%S %p  ", localtime())))
    print("[+] Made By: vkiko2")
    print("[+] Made Date: 08/02/2017 (DD/MM/YYYY)")
    print("[+] Script version: 1.0")
    print("[+] Game Version: GMS 182.1 (Should work for more)")
    print("[+] ==================================================")

    # Save start time for calculating execution time
    script_start_time = time.clock()

    # Update Adresses
    update_ms_aString()
    update_ms_nSize()

    # Make a list of unencrypted strings
    # (Yes, we are reading them all into memory.)
    # (Boo-hoo)
    out_strings = []
    total_len = 0
    for i in range(0, ms_nSize):
        out_strings.append(get_string_at_idx(i))
        total_len += len(out_strings[i])+1
        #print(u"{}: \"{}\"".format(i, get_string_at_idx(i)))
    print("[+] Decrypted {} strings in memory.".format(len(out_strings)))

    # Check if the strings will fit within the segment we're gonna create
    if total_len >= SCRIPT_SEGMENT_SIZE:
        print("[!] total_len() ({}) > SCRIPT_SEGMENT_SIZE({})".format(total_len, SCRIPT_SEGMENT_SIZE))
        print("[!] This is probably an error, if not bump up SCRIPT_SEGMENT_SIZE.")
        FATAL()

    print("[+] Strings will fill {:.2f}% [{}/{} bytes] of the new segment.".format((float(total_len)/float(SCRIPT_SEGMENT_SIZE))*100.0, total_len, SCRIPT_SEGMENT_SIZE))

    # Get the stringpool calls
    sp_calls = get_string_pool_calls()
    total_sp_call_count = 0
    for idx, call_addrs in sp_calls.iteritems():
        for addr in call_addrs:
            total_sp_call_count += 1
    print("[+] StringPool::ms_nSize: {}".format(ms_nSize))
    print("[+] Found stringpool calls for {} ids. {} calls total.".format(len(sp_calls), total_sp_call_count))

    # Create the new segment and write the strings to it
    msspd_ea = make_new_segment()
    seg_str_dict = write_segment_strings(msspd_ea, out_strings)

    choice = AskYN(0, "Add experimental decompiler comments? (This takes a VERY long time, roughly an entire day)")
    if choice == 1:
        global USE_EXP_DECOMP_COMMENT
        USE_EXP_DECOMP_COMMENT = True

    # Add the xrefs and comments to for each stringpool call
    for idx, call_addrs in sp_calls.iteritems():
        for addr in call_addrs:
            if not idc.add_dref(addr, seg_str_dict[idx], dr_R):
                print("[-] Failed to add data xref from {} to {}. Skipping.".format(addr, seg_str_dict[idx]))
            try_make_comment(addr, "[IDX{}] \"{}\"".format(idx, out_strings[idx].encode("utf8", 'ignore')))#encode('cp949', 'ignore'))) ############################

    print("[+] Execution time: {}".format(time.clock() - script_start_time))
    print("[+] The script has been completed.")
    print("[+] Have a nice day!")
    print("[+] ==================================================\n")

if __name__ == "__main__":
    main()
