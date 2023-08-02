import idaapi
usc2_LATIN_SPECIAL_START = [0x20, 0x00]
usc2_LATIN_SPECIAL_END = [0x40, 0x00]
usc2_LATIN_CAP_START = [0x41, 0x00]
usc2_LATIN_CAP_END = [0x5A, 0x00]
usc2_LATIN_LOW_START = [0x61, 0x00]
usc2_LATIN_LOW_END = [0x7A, 0x00]
usc2_LATIN_SPECIAL2_START = [0x7B, 0x00]
usc2_LATIN_SPECIAL2_END = [0x7F, 0x00]

def is_ascii(data):
    """determines if the data string is ascii or not"""
    try:
        encoding = chardet.detect(data)
        if encoding['encoding'] == 'ascii':
            return True
    except ValueError:
        return False


def is_unicode(data):
    """determines if the data string is unicode or not"""
    try:
        encoding = chardet.detect(data)
        if encoding['encoding'] == 'unicode':
            return True
    except ValueError:
        return False


ascii_string = idaapi.get_many_bytes(0x02BE28A0, 8)#0x02BE281C, 12)#0x02BE280C, 12)
print(ascii_string)
if is_ascii(ascii_string):
    print("ascii_string is ascii")
if is_unicode(ascii_string):
    print("ascii_string is unicode")

unicode_string = idaapi.get_many_bytes(0x02BE28B4, 8)
print(unicode_string)
if is_ascii(unicode_string):
    print("unicode_string is ascii")
if is_unicode(unicode_string):
    print("unicode_string is unicode")


