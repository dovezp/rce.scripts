from __future__ import print_function

import idaapi
import idautils
import idc


def main():
    for fva in idautils.Functions():
        print_all_bbs(fva)


def print_all_bbs(fva):
    function = idaapi.get_func(fva)
    flowchart = idaapi.FlowChart(function)
    print("Function starting at 0x%x consists of %d basic blocks" % (function.start_ea, flowchart.size))
    for bb in flowchart:
        print(format_bb(bb))
        for succ in bb.succs():
            print("  -> %s" % format_bb(succ))


def format_bb(bb):
    bbtype = {0: "fcb_normal", 1: "fcb_indjump", 2: "fcb_ret", 3: "fcb_cndret",
              4: "fcb_noret", 5: "fcb_enoret", 6: "fcb_extern", 7: "fcb_error"}
    return("ID: %d, Start: 0x%x, End: 0x%x, Last instruction: 0x%x, Size: %d, "
           "Type: %s" % (bb.id, bb.start_ea, bb.end_ea, idc.prev_head(bb.end_ea),
                         (bb.end_ea - bb.start_ea), bbtype[bb.type]))


if __name__ == "__main__":
    main()