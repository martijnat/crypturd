#!/usr/bin/env python2
def add_padding(s,n):
    "Pad input to a multiple of n bytes"
    if n<1:
        raise Exception
    pad_length = n-(len(s)%n)
    if pad_length > 255:
        raise Exception
    elif pad_length==0:
        pad_length = n
    return s + chr(pad_length)*pad_length

def remove_padding(s):
    pad_length = ord(s[-1])
    for i in range(pad_length):
        if ord(s[-1-i]) != pad_length:
            raise Exception
    return s[:-pad_length]
