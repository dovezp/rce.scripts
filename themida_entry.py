'''
    Themida Entry Peel
    -- Documentation is in my notes and video tutorials :)

    Decode 1st block in the encode segment
    @version 02/23/2017
'''


'''
    copied interior from the second function, decode_buffer
'''
def decrypt(location, key1, key2):
    location ^= key1
    location += key2
    return location

'''
    returns interior decode to save line space
'''
def decrypt_this(location, key1, key2):
    return decrypt(Dword(location), key1, key2)

'''
    decode loop
'''
def decode_buffer(location, length, key1, key2):
    for i in range(0, length):
        val = decrypt_this(location + i * 4, key1, key2)
        PatchDword(location + i * 4, val)

'''
    start of encode segment: 0x03128000
    buffer length: 0x400
    xor key: 0x334A3237
    inc key: 0x53FE16F0
'''
decode_buffer(0x3233008, 0x400, 0x2E188729, 0x40B2470)
print("decoded 0x400 of .encode segment")
