#!/usr/bin/env python2

def random_mod(m):
    x = ord(os.urandom(1)[0])
    while x>=m:
        x = ord(os.urandom(1)[0])
    return m

def xor_str(s1,s2):
    "xor two strings of equal size"
    return "".join([chr(ord(c1)^ord(c2)) for c1,c2 in zip(s1,s2)])
def add_PKCS7_padding(s,n):
    "Pad input to a multiple of n bytes"
    if n<1:
        raise Exception
    pad_length = n-(len(s)%n)
    if pad_length > 255:
        raise Exception
    elif pad_length==0:
        pad_length = n
    return s + chr(pad_length)*pad_length
