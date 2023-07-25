from __future__ import print_function

import idaapi
import idautils
import idc


def main():
    for fva in idautils.Functions():
        f = idaapi.get_func(fva)
        junk_bbs = get_junk_bbs(f)
        while make_bbs_unkn(junk_bbs) != 0:
            junk_bbs = get_junk_bbs(f)


def get_junk_bbs(function):
    """ Return list of basic block address tuples that do not have any predecessor blocks for given
    function. """
    all_bbs = set([])
    referenced_bbs = set([])
    flowchart = idaapi.FlowChart(function)
    for bb in flowchart:
        # get start and end for all basic blocks in function
        all_bbs.add((bb.startEA, bb.endEA))
        # get start and end for function start basic block
        if bb.startEA == function.startEA:
            referenced_bbs.add((bb.startEA, bb.endEA))
        # get start and end for all basic blocks that have a predecessor
        for succ in bb.succs():
            referenced_bbs.add((succ.startEA, succ.endEA))
    return all_bbs - referenced_bbs


def make_bbs_unkn(bbs):
    """ Return number of removed basic blocks. """
    for bb in bbs:
        size = bb[1] - bb[0]
        print("removing basic block of size %d starting at 0x%x and ending at 0x%x" % (size, bb[0],
                                                                                       bb[1]))
        idc.MakeUnknown(bb[0], size, idc.DOUNK_SIMPLE)
    return len(bbs)


if __name__ == "__main__":
    main()
