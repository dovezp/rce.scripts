# Themida 1.8 CISC unvirtualizer for IDA 7.5

def debug(s, indent=1):
    print("{{:<{}}}{{}}".format(indent*4).format(" ", s))
def error(s, indent=1):
    print("{{:<{}}}{{}}".format(indent*4).format("[!]", s))


def define_vmcontext(handler_len):
    import ida_bytes
    import ida_struct
    import ida_typeinf
    struct_id = ida_struct.add_struc(BADADDR, "VMContext")
    if struct_id == BADADDR: # VMContext struct already exists
        ida_struct.del_struc(ida_struct.get_struc(ida_struct.get_struc_id("VMContext"))) # delete existing struct
        struct_id = ida_struct.add_struc(BADADDR, "VMContext") # add it again
    struct_p = ida_struct.get_struc(struct_id)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_ecx", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_eax", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_edx", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_edi", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_ebx", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_esi", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_ebp", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "vm_efl", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "jxx_flag", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "counter", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "index_of_ecx_in_ctx", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "delta_offset", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "busy", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "field_34", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "field_38", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "reloc_offset", BADADDR, ida_bytes.dword_flag(), None, 4)
    assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "field_40", BADADDR, ida_bytes.dword_flag(), None, 4)
    if handler_len > 0:
        #assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "handlers", BADADDR, ida_bytes.dword_flag(), None, 4*handler_len)
        assert ida_struct.STRUC_ERROR_MEMBER_OK == ida_struct.add_struc_member(struct_p, "handlers", BADADDR, ida_bytes.dword_flag(), None, 4)
        tinfo_voidp_p = ida_typeinf.tinfo_t()
        tinfo_voidp_p.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BT_VOID))
        tinfo_array_p = ida_typeinf.tinfo_t()
        tinfo_array_p.create_array(tinfo_voidp_p, handler_len, 0)
        ida_struct.set_member_tinfo(struct_p, ida_struct.get_member_by_name(struct_p, "handlers"), 0, tinfo_array_p, 0)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "vm_ebx"), "this is not esp, but ebx, vm does not switch stacks and does not have to keep esp", False)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "jxx_flag"), "whether to perform a control transfer flag", False)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "counter"), "used when simulating a control transfer instruction", False)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "index_of_ecx_in_ctx"), "the index of ecx in ctx, used when imitating jcxz/jecxz", False)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "delta_offset"), "alignment", False)
    assert ida_struct.set_member_cmt(ida_struct.get_member_by_name(struct_p, "reloc_offset"), """offset for processing relocation data""", False)

def set_vmcontext(ea):
    import ida_bytes
    import ida_name
    ida_bytes.del_items(ea)
    vmcontext_tid = ida_struct.get_struc_id("VMContext")
    assert vmcontext_tid != BADADDR, "VMContext struct not defined!"
    struct_p = ida_struct.get_struc(vmcontext_tid)
    ida_name.set_name(ea, "vm_context", ida_name.SN_NON_PUBLIC | ida_name.SN_NON_WEAK | ida_name.SN_AUTO)
    ida_bytes.create_data(ea, ida_bytes.stru_flag(), ida_struct.get_max_offset(struct_p), vmcontext_tid)

def find_vms():
    import idautils
    import ida_allins
    import ida_segment
    import ida_ua
    import ida_name

    # or just use idautils.Segments() but whatever
    segments = [ida_segment.get_first_seg()]
    while True:
        seg = ida_segment.get_next_seg(segments[-1].start_ea)
        if seg is None:
            break
        else:
            segments.append(seg)

    vms = []
    for segment_p in segments:
        debug("looking in {}".format(ida_segment.get_segm_name(segment_p)))
        for func_ea in idautils.Functions(segment_p.start_ea, segment_p.end_ea):
            for (chunk_start_ea, chunk_end_ea) in idautils.Chunks(func_ea):
                instructions = idautils.Heads(chunk_start_ea, chunk_end_ea)
                insn = ida_ua.insn_t()
                is_fish_vm = False

                # decode first push
                _length = ida_ua.decode_insn(insn, next(instructions))
                if insn.itype != ida_allins.NN_push:
                    continue # opcode is not a push
                if insn.ops[0].type != ida_ua.o_imm:
                    continue # operand is not an immediate


                _length = ida_ua.decode_insn(insn, next(instructions))
                if insn.itype == ida_allins.NN_push:
                    if insn.ops[1].type != ida_ua.o_imm:
                        continue
                    is_fish_vm = True # possible fish vm
                    _length = ida_ua.decode_insn(insn, next(instructions))

                if insn.itype != ida_allins.NN_jmp:
                    continue
                if insn.ops[0].type != ida_ua.o_near:
                    continue # operand is not a near jump
                if len(list(idautils.XrefsTo(insn.ops[0].addr))) < 10:
                    continue # probably false positive

                vms.append([chunk_start_ea, insn.ops[0].addr]) # (vm caller, vm jump addr to dispatch init)
                if is_fish_vm:
                    debug("[{:>8}.{:08x}] {} : FISH vm found".format(ida_segment.get_segm_name(segment_p), func_ea, ida_name.get_ea_name(chunk_start_ea)), 2)
                else:
                    debug("[{:>8}.{:08x}] {} : CISC or RISC vm found".format(ida_segment.get_segm_name(segment_p), func_ea, ida_name.get_ea_name(chunk_start_ea)), 2)
    return vms

def find_lodsb(ea):
    import ida_allins
    import ida_bytes
    import ida_ua
    insn = ida_ua.insn_t()
    i = 0
    while i < 1000: # arbitrary search limit
        insn_ea = ida_xref.get_first_cref_from(ea) #should get either the xref if its a jump or call, or the next instruction
        if insn_ea == BADADDR: # no references to jump to
            #print("no references to jump to!")
            insn_ea = ida_bytes.next_head(ea, BADADDR) # hail mary to get the next instruction
            if insn_ea == BADADDR: # end of function chunk maybe
                error("no next head available!")
                break
        #else:
        #    print("cref {:08x} -> {:08x}".format(ea, insn_ea))
        _length = ida_ua.decode_insn(insn, insn_ea)
        ea = insn_ea
        if insn.itype == ida_allins.NN_lods:
            debug("[{:08x}] found lodsb ({})".format(ea, ida_name.get_ea_name(ea)))
            return ea
        i += 1
    error("failed to find lodsb!")

def backtrace_crefs(ea):
    import ida_allins
    import ida_bytes
    import ida_ua
    import ida_xref
    insn = ida_ua.insn_t()
    history = []
    while True:
        new_ea = ida_xref.get_first_cref_to(ea) # this will be the previous head if no xrefs to
        if new_ea == BADADDR or not ida_ua.can_decode(ea):
            # cant decode anymore or no more xrefs to addr
            return ea
        else:
            if new_ea in history:
                debug("loop detected, using previous head instead")
                new_ea = ida_bytes.prev_head(ea, 0)
                if new_ea == BADADDR:
                    debug("prev head is BADADDR, guess this is the top?")
                    return new_ea
            ea = new_ea
            _length = ida_ua.decode_insn(insn, ea)
            if insn.itype == ida_allins.NN_call and insn.ops[0].type == ida_ua.o_near and insn.ops[0].value == 0:
                debug("call $+5 found, stopping search for safety; this is probably the dispatcher")
                return None
            history.append(ea)

class Context:
    def __init__(self, vm_context_start, vm_caller, dispatch_init, dispatch):
        import ida_bytes
        import ida_struct
        vmcontext_tid = ida_struct.get_struc_id("VMContext")
        assert vmcontext_tid != BADADDR, "VMContext struct not defined!"
        struct_p = ida_struct.get_struc(vmcontext_tid)
        debug("populating vm context from memory at {:08x}".format(vm_context_start))
        self.vm_context_start = vm_context_start
        self.vm_caller = vm_caller
        self.dispatch_init = dispatch_init
        self.dispatch = dispatch
        self.delta_offset = ida_bytes.get_dword(vm_context_start + ida_struct.get_member_by_name(struct_p, "delta_offset").soff)
        self.handlers_start = vm_context_start + ida_struct.get_member_by_name(struct_p, "handlers").soff
        self.handlers_end = vm_context_start + ida_struct.get_member_by_name(struct_p, "handlers").eoff
        self.handlers_ref = []
        for i in range(0, int((self.handlers_end - self.handlers_start) / 4)):
            self.handlers_ref.append(vm_context_start + ida_struct.get_member_by_name(struct_p, "handlers").soff + i * 4)
        self.handlers = [ida_bytes.get_dword(ref) for ref in self.handlers_ref]

    def get_opcode_stream_start(self, push_addr=None):
        import ida_allins
        import ida_ua
        insn = ida_ua.insn_t()
        # decode first push
        if push_addr is None:
            push_addr = self.vm_caller
        _length = ida_ua.decode_insn(insn, push_addr)
        if insn.itype != ida_allins.NN_push:
            error("[{:08x}] opcode at address is not push".format(push_addr))
            raise Exception("opcode at address is not push") # opcode is not a push
        if insn.ops[0].type != ida_ua.o_imm:
            error("[{:08x}] operand at address is not an immediate".format(push_addr))
            raise Exception("operand at address is not an immediate") # operand is not an immediate
        ret = int(insn.ops[0].value + self.delta_offset) & 0xFFFFFFFF
        if not ida_ua.can_decode(ret):
            error("[{:08x}] data at {:08x} ({:08x} + {:08x}) is not a valid address".format(push_addr, ret, insn.ops[0].value, self.delta_offset))
            raise Exception("invalid opcode stream address")
        return ret


import idautils
import ida_bytes
import ida_search
import ida_struct
import ida_ua

print("================================================================================")
print("============================= tmd 1.8 unvirt ===================================")
print()
print("finding VMs")
vms = find_vms()
[vm, dispatch_addr] = vms[1]
# 1. find losdb in the vm
# 2. find & backtrace all crossreferences to lodsb (these are (mostly) the handlers)
# 3. find handler reference via binary search for the root of the handler
#    immediate search will fail if not interpreted as a number (eg. offset sub_xxxxxx)
#    xref search will fail if if the location is not defined correctly by IDA's autoanalysis
# 4. remove false positives by testing *(dword*)handler_ea is actually decodable
ea = find_lodsb(vm)
xrefs = [x.frm for x in idautils.XrefsTo(ea)]
#handler_ea = backtrace_crefs(xrefs[0x8d])
print("looking in vm at {:08x} for possible handlers".format(vm))
debug("found {} xrefs for vm {:08x}".format(len(xrefs), vm))
handlers = []
for xref in xrefs:
    #print("{:08x} backtracing cref".format(xref))
    handler_ea = backtrace_crefs(xref)
    if handler_ea is None:
        continue
    #print("{:08x} find_binary".format(handler_ea))
    xref_ea = 0
    while xref_ea != BADADDR: # add all instances that are found, some might be false positive
        xref_ea = ida_search.find_binary(xref_ea, BADADDR, str(handler_ea), 10, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT)
        if xref_ea != BADADDR:
            handlers.append(xref_ea)
handlers.sort()
assert len(handlers) > 10 # sanity check
print("pruning false positives from handlers...")
pruned = [handler for handler in handlers if not ida_ua.can_decode(ida_bytes.get_dword(handler))]
handlers = [handler for handler in handlers if ida_ua.can_decode(ida_bytes.get_dword(handler))]
print("pruned {} handlers: {}".format(len(pruned), ", ".join("{:08x}".format(ea) for ea in pruned)))
#print("found {} possible handlers: {}".format(len(handlers), ", ".join("{:08x}".format(ea) for ea in handlers)))
print("found {} possible handlers".format(len(handlers)))

handler_ea = handlers[0]
# work backwards from the first handler without a huge delta (just to be safe) until zeroes are reached
# then subtract size of vm context to get base
for i in range(0, len(handlers) - 1):
    if abs(handlers[i] - handlers[i + 1]) == 4:
        handler_ea = handlers[i]
        debug("working backwards from {:08x}".format(handler_ea))
        break
        #print("wat", hex(handlers[i]), hex(handlers[i + 1]))
insn = ida_ua.insn_t()
while ida_ua.decode_insn(insn, ida_bytes.get_dword(handler_ea - 4)) > 0:
    handler_ea -= 4

handler_array_ea = handler_ea
debug("guessing handler array starts at {:08x}".format(handler_array_ea))




# guess how many handlers there are; should be one contiguous array of valid function pointers
handlers = []
for i in range(0, 1024):
    if ida_ua.decode_insn(insn, ida_bytes.get_dword(handler_array_ea + i*4)) == 0:
        break
    handlers.append(ida_bytes.get_dword(handler_array_ea + i*4))
print("final handler count {0:} ({0:02x}) @ {1:08x} : {2:}".format(len(handlers), handler_array_ea, ", ".join("{:08x}".format(ea) for ea in handlers)))


print("defining VMContext struct with zero handlers")
define_vmcontext(0) # define VMContext without any handlers for now to get size without handlers
vmcontext_tid = ida_struct.get_struc_id("VMContext")
assert vmcontext_tid != BADADDR, "VMContext struct not defined!"
struct_p = ida_struct.get_struc(vmcontext_tid)
vmcontext_base = handler_ea - ida_struct.get_max_offset(struct_p)
debug("guessing VMContext starts at {:08x}".format(vmcontext_base))
print("redefining VMContext struct with {} handlers".format(len(handlers)))
define_vmcontext(len(handlers))

print("defining vmcontext at {:08x}".format(vmcontext_base))
set_vmcontext(vmcontext_base)

print("(re)defining handler offsets as code (ida_ua.create_insn)")
for handler in handlers:
    if not ida_bytes.is_code(ida_bytes.get_flags(handler)):
        debug("undefining non-code item at {:08x}".format(handler))
        ida_bytes.del_items(handler)
    ida_ua.create_insn(handler)

context = Context(vmcontext_base, vm, dispatch_addr, find_lodsb(dispatch_addr))




#insn = ida_ua.insn_t()
#ida_ua.decode_insn(insn, 0x48206C)
#insn.ops[0].type
#insn.ops[0].value

#set_vmcontext(0x00481D89)

#ea = 0x48a092
#ida_funcs.get_func_name(ea)
