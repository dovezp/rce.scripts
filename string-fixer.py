
import idc
import idaapi
import idautils



# UTF-16LE CLEAN!


# idc.MakeStr(idc.here(), 0)

# idaapi.make_ascii_string()


# make ascii c
# 2 = len
# make_ascii_string(idc.here(), 2, 0)

# make unicode 16
# 2 = len
# make_ascii_string(idc.here(), 2, 1)


def aob_matches(str_segment, str_signature):
    arrr = []
    count = 0
    str_signature = str(str_signature)
    if str_signature == "":
        return False

    adrs = idc.FindBinary(0, idc.SEARCH_DOWN, str_signature)
    if idc.SegName(adrs) == str_segment:
        if adrs != idc.BADADDR:
            if (0x20 <= idc.Byte(adrs) <= 0x7E) and (0x20 <= idc.Byte(adrs + 2) <= 0x7E) and idc.Byte(adrs) != 0x0:
                count += 1
                arrr.append(adrs)

    while adrs != idc.BADADDR:
        adrs = idc.FindBinary(adrs + 1, idc.SEARCH_DOWN, str_signature)
        if idc.SegName(adrs) == str_segment:
            if adrs != idc.BADADDR:
                if (0x20 <= idc.Byte(adrs) <= 0x7E) and (0x20 <= idc.Byte(adrs + 2) <= 0x7E) and idc.Byte(adrs) != 0x0:
                    count += 1
                    arrr.append(adrs)

    return arrr, count


addresses, c = aob_matches(".rdata", "?? 00 ?? 00 ?? 00") # ?? 00 ?? 00")

# clean up

addresses = list(set(addresses))
addresses = sorted(addresses)
print("before: " + str(len(addresses)))


new_addresses = []
prev_address = addresses[0]
prev_end = idc.FindBinary(addresses[0] + 1, idc.SEARCH_DOWN, "00 00 00")

for i in range(0, len(addresses)):
    peak_end = idc.FindBinary(addresses[i] + 1, idc.SEARCH_DOWN, "00 00 00")
    if peak_end == prev_end:
        if addresses[i] > prev_address:
            addresses[i] = prev_address
    #        prev_end = peak_end
    # else:
    prev_end = peak_end
    prev_address = addresses[i]


addresses = list(set(addresses))
addresses = sorted(addresses)
print("after: " + str(len(addresses)))

# print(new_addresses)


print("--------------------------------------------------")


for address in addresses:
    peak_end = idc.FindBinary(address + 1, idc.SEARCH_DOWN, "00 00 00")
    size = int(peak_end - address) + 1
    # print("----------------------------------------------------------")
    #print("start: " + str(hex(int(address))))
    #print("end: " + str(hex(int(peak_end))))
    #print("size: " + str(int(size)))

    if (peak_end - address) <= 255:
        peak_start = address
        internally_safe = True
        while (peak_start <= peak_end) and internally_safe is True:
            b = int(idc.Byte(peak_start))
            # print(str(hex(int(peak_start))) + " @ " + str(hex(b)))
            if not (0x20 <= b <= 0x7E) or b == 0x00:
                internal_check = False
                # print("invalid string")
            peak_start += 2

        if internally_safe:
            idaapi.do_unknown_range(address, size, idc.DELIT_EXPAND)
            status = idaapi.make_ascii_string(address, size, 1)
            if status:
                #print("FIRST: string made @ " + str(hex(int(address))) + " of size: " + str(int(size)) + " to end: " + str(hex(int(peak_end))))
                pass
            else:
                # ending slightly off
                print("WARNING IS STRUCT OR REF:  @ " + str(hex(int(address))) + " of size: " + str(int(size)) + " to end: " + str(hex(int(peak_end))))


        # break after one address
        # break

# 0x40 -> 0x7E

idaapi.refresh_strlist()
