import idc
import idaapi
import idautils
import string


class strings:
    def __init__(self):
        self.DATA = 3
        pass

    def get_start_ea(self, attr):
        ea = idc.BADADDR
        seg = idc.FirstSeg()

        while seg != idc.BADADDR:
            if idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE) == attr:
                ea = seg
                break
            else:
                seg = idc.NextSeg(seg)

        return ea

    def stringify(self):
        n = 0
        ea = self.get_start_ea(self.DATA)

        if ea == idc.BADADDR:
            ea = idc.FirstSeg()

        print ("Looking for possible strings starting at: %s:0x%X..." % (idc.SegName(ea), ea)),

        for s in idautils.Strings():
            print(s)
            # if s.ea > ea:
            #    if not idc.isASCII(idc.GetFlags(s.ea)) and idc.MakeStr(s.ea, idc.BADADDR):
            #        n += 1

       # print "created %d new ASCII strings" % n


s = strings()
s.stringify()


