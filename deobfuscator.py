import ida_bytes
import ida_funcs
import ida_ida
import ida_idp
import ida_name
import ida_segment
import ida_ua
import idaapi
import idc

import signatures

xobf_seg = None

total_segments = 0


def tohex(val, nbits):
    # do resolve for proper subtraction
    # 32 and 64 nbits
    # hex(-199703103 & (2**32-1)) # 32-bit
    # '0xf418c5c1L'
    # hex(-199703103 & (2**64-1)) # 64-bit
    # '0xfffffffff418c5c1L'
    return hex((val + (1 << nbits)) % (1 << nbits))


def get_first_operand_value(address):
    return idc.get_operand_value(address, 0)


def get_second_operand_value(address):
    return idc.get_operand_value(address, 1)


def get_mnemonic(address):
    return idc.print_insn_mnem(address)


# THIS IS FOR x86 RESOLVING xObf
XOBF_SEGMENT = idaapi.get_segm_by_name('.xObf')
LAST_SEGMENT = idaapi.get_last_seg()
#
if XOBF_SEGMENT.start_ea != LAST_SEGMENT.start_ea:
    # we know xObf is appended to the last segment anything else is prob fake
    exit(1)

TEXT_SEGMENT = idaapi.get_segm_by_name('.text')
FIRST_SEGMENT = idaapi.get_first_seg()
#
if TEXT_SEGMENT.start_ea != FIRST_SEGMENT.start_ea:
    # we know text is appended to the first segment anything else is prob fake
    exit(1)

ENTRY_POSITONS = []


def resolve_lea_operation(address):
    '''
    addition = re.findall('\[(.*)\]', idc.generate_disasm_line(address, 0))[0].split('+')
    if len(addition) != 0:
        return "+"
    subtraction = re.findall('\[(.*)\]', idc.generate_disasm_line(address, 0))[0].split('-')
    if len(subtraction) != 0:
        return "-"
    '''
    if len(idc.generate_disasm_line(address, 0).split('-')) == 2:
        return '-'
    if len(idc.generate_disasm_line(address, 0).split('+')) == 2:
        return '+'


def resolve_lea_offset(address):
    i = ida_ua.insn_t()
    # same as idc.GetOptype, just a different way of accessing the types
    idaapi.decode_insn(i, address)

    if i.Op2.type in (idaapi.o_displ, idaapi.o_phrase):
        specflag1 = i.Op2.specflag1
        specflag2 = i.Op2.specflag2
        scale = 1 << ((specflag2 & 0xC0) >> 6)
        offset = i.Op2.addr

        if specflag1 == 0:
            index = None
            base_ = i.Op2.reg
        elif specflag1 == 1:
            index = (specflag2 & 0x38) >> 3
            base_ = (specflag2 & 0x07) >> 0
            if i.Op2.reg == 0xC:
                if base_ & 4:
                    base_ += 8
                if index & 4:
                    index += 8

        if offset != 0:
            return offset
    return None


def validate_entry(address):
    callee_address = get_first_operand_value(address)
    possible_entry_address = idaapi.find_binary(callee_address, XOBF_SEGMENT.end_ea, "8F 05 ?? ?? ?? ?? 50", 0,
                                                idaapi.SEARCH_DOWN)
    if callee_address == possible_entry_address:
        ENTRY_POSITONS.append((address, callee_address))
        idc.create_insn(address)
        idc.create_insn(callee_address)
        ida_bytes.del_items(address + 5, 2, ida_bytes.DELIT_EXPAND)
        return True
    if possible_entry_address in [idaapi.BADADDR, 0]:
        ida_bytes.del_items(address, 5, ida_bytes.DELIT_EXPAND)
        return False
    ida_bytes.del_items(address, 5, ida_bytes.DELIT_EXPAND)
    return False


def find_entry_call(address):
    possible_entry_address = idaapi.find_binary(
        address,
        TEXT_SEGMENT.end_ea,
        f"{signatures.XOBF_CALL_INTO} ?? ?? ?? ??",
        0,
        idaapi.SEARCH_DOWN,
    )
    if (
        not ida_bytes.is_code(ida_bytes.get_full_flags(possible_entry_address))
        or get_mnemonic(possible_entry_address) != signatures.XOBF_CALL_INTO
    ):
        ida_bytes.del_items(possible_entry_address, 2, ida_bytes.DELIT_EXPAND)
        idc.create_insn(possible_entry_address)
    if possible_entry_address in [idaapi.BADADDR, 0]:
        ida_bytes.del_items(possible_entry_address, 5, ida_bytes.DELIT_EXPAND)
        return -1
    elif validate_entry(possible_entry_address):
        return possible_entry_address
    else:
        ida_bytes.del_items(possible_entry_address, 5, ida_bytes.DELIT_EXPAND)
        return 0


def seek_entry():
    # Method 1 (biased approach)
    current_address = TEXT_SEGMENT.start_ea
    while current_address <= TEXT_SEGMENT.end_ea:
        next_iter = find_entry_call(current_address)
        if next_iter <= 0:
            current_address += 1
        elif next_iter > 1:
            current_address = next_iter
            current_address += 1
        else:
            print(
                f"ERROR.SeekingIteration: Issue obtaining a valid macro block to search from at {hex(current_address)}"
            )
            break

    print("============================================================")


def eval_hidden_instruction(caller, address):
    ida_bytes.del_items(address, 2, ida_bytes.DELIT_EXPAND)
    idc.create_insn(address)
    obf_value_offset = _extracted_from_eval_hidden_instruction_()
    real_bytes = _extracted_from_eval_hidden_instruction_()
    mov_address = address + 7
    pop_store_address = get_first_operand_value(address)
    lea_return_address = _extracted_from_eval_hidden_instruction_()
    if idc.get_wide_byte(mov_address) == 0xB8:
        obf_value_offset = _extracted_from_eval_hidden_instruction_16(mov_address)
    elif idc.get_wide_byte(mov_address) == 0x8B:
        obf_value_offset = _extracted_from_eval_hidden_instruction_16(mov_address)
    elif idc.get_wide_byte(mov_address) == 0x90:
        mov_address = address + 8
        obf_value_offset = _extracted_from_eval_hidden_instruction_16(mov_address)
    else:
        obf_value_offset = -1

    mov_size = idc.get_item_size(mov_address)
    if mov_size == 6:
        obf_value_offset = idc.get_wide_dword(obf_value_offset)

    print("\t MOV EAX OBF VAL: " + hex(obf_value_offset))
    if obf_value_offset != -1:
        _extracted_from_eval_hidden_instruction_(
            mov_address, obf_value_offset, pop_store_address, caller
        )


# TODO Rename this here and in `eval_hidden_instruction`
def _extracted_from_eval_hidden_instruction_(mov_address, obf_value_offset, pop_store_address, caller):
    lea_address = mov_address + idc.get_item_size(mov_address)
    lea_value = resolve_lea_offset(lea_address)
    print("\t LEA VAL: " + hex(lea_value))
    eval_equation = f"{str(obf_value_offset)}+{str(lea_value)}"
    real_bytes = tohex(eval(eval_equation), 32)
    print("\t REAL BYTES: " + real_bytes)
    xchg_address = lea_address + 6
    if idc.get_wide_byte(xchg_address) == 0x87:
        _extracted_from_eval_hidden_instruction_(
            xchg_address, real_bytes, pop_store_address, caller
        )


# TODO Rename this here and in `eval_hidden_instruction`
def _extracted_from_eval_hidden_instruction_(xchg_address, real_bytes, pop_store_address, caller):
    key_offset = get_second_operand_value(xchg_address)
    print("\t KEY OFFSET: " + hex(key_offset))

    ida_bytes.patch_dword(key_offset, int(real_bytes, 16))
    ida_bytes.del_items(key_offset, 2, ida_bytes.DELIT_EXPAND)
    idc.create_insn(key_offset)

    lea_return_address = pop_store_address + 4
    if idc.get_wide_byte(lea_return_address) == 0x87:
        # xchg
        # no buffer to return...
        xchg_return_address = caller + 5
        print("\t XCHG TO RETURN ADDRESS: " + hex(xchg_return_address))
    elif idc.get_wide_byte(lea_return_address) == 0x8D:
        # lea
        lea_offset = resolve_lea_offset(lea_return_address)
        print("\t LEA RETURN OFFSET: " + hex(lea_offset))
        lea_return_address = caller + 5 + lea_offset
        print("\t LEA TO XCHG TO RETURN ADDRESS: " + hex(lea_return_address))

    start_end_address = idaapi.find_binary(key_offset + 4, key_offset + 24, "50 66 B8 ?? ?? 66", 0,
                                           idaapi.SEARCH_DOWN)
    print("\t START END ADDRESS: " + hex(start_end_address))
    deobfuscated_bytecode = ida_bytes.get_bytes(key_offset, start_end_address - key_offset)
    if deobfuscated_bytecode is None:
        print(f"!!!!!!!!!!!!!!!!!!!!!!!!FAILED TO DEOBFUSCATE: {hex(caller)}")

    else:
        print("\t DEOBFUSCATED: " + hex(caller) + " with bytes: " + str(deobfuscated_bytecode))
        ida_bytes.patch_bytes(caller, deobfuscated_bytecode)
        if idc.get_wide_byte(caller) == 0xE8:
            ida_idp.assemble(caller, 0, caller, True, "call 0%08xh" % get_first_operand_value(key_offset))
            print("\t RESOLVED OUT OF SEGMENT CALLS: " + hex(caller))


# TODO Rename this here and in `eval_hidden_instruction`
def _extracted_from_eval_hidden_instruction_():
    xchg_address = 0
    key_offset = 0
    return 0


# TODO Rename this here and in `eval_hidden_instruction`
def _extracted_from_eval_hidden_instruction_():
    return _extracted_from_eval_hidden_instruction_()


# TODO Rename this here and in `eval_hidden_instruction`
def _extracted_from_eval_hidden_instruction_16(mov_address):
    ida_bytes.del_items(mov_address, 2, ida_bytes.DELIT_EXPAND)
    idc.create_insn(mov_address)
    return get_second_operand_value(mov_address)


if __name__ == '__main__':
    try:
        seek_entry()
        if len(ENTRY_POSITONS) > 0:
            ENTRY_POSITONS.sort(key=lambda x: x[1])
            for i in ENTRY_POSITONS:
                print(hex(i[0]) + "\t" + hex(i[1]))
                print("\t STORE RETURN TO CALLER ADDRESS: " + hex(get_first_operand_value((i[1]))))
                print("\t RETURN CALLER ADDRESS: " + hex(i[0] + 5))
                ida_bytes.patch_dword(get_first_operand_value((i[1])), i[0] + 5)

                eval_hidden_instruction(i[0], i[1])
                print("---")

            ida_segment.del_segm(XOBF_SEGMENT.start_ea, ida_segment.SEGMOD_KILL | ida_segment.SEGMOD_SILENT)

            # Brute-force nuke all info from all the heads
            ea = ida_ida.cvar.inf.min_ea
            while ea != idc.BADADDR and ea <= ida_ida.cvar.inf.max_ea:
                if seg := ida_segment.getseg(ea):
                    if seg.type not in [ida_segment.SEG_XTRN, ida_segment.SEG_DATA, ida_segment.SEG_NORM,
                                        ida_segment.SEG_BSS]:
                        ida_segment.set_segment_cmt(seg, "", False)
                        ida_segment.set_segment_cmt(seg, "", True)

                        ida_name.del_local_name(ea)
                        ida_name.del_global_name(ea)
                        if func := ida_funcs.get_func(ea):
                            ida_ida.del_func_cmt(func, False)
                            ida_ida.del_func_cmt(func, True)
                            ida_funcs.del_func(ea)
                        ida_bytes.del_hidden_range(ea)
                ea = ida_bytes.next_head(ea, ida_ida.cvar.inf.max_ea)
            ea = TEXT_SEGMENT.start_ea
            while ea != idc.BADADDR and ea <= TEXT_SEGMENT.end_ea:
                ida_bytes.del_items(ea, 1, ida_bytes.DELIT_EXPAND)
                ea += 1

    except Exception as e:
        print(e)
