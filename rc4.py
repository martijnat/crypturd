#!/usr/bin/env python2

#  ____   ____ _  _     _                   _                                  _
# |  _ \ / ___| || |   (_)___   _ __   ___ | |_   ___  ___  ___ _   _ _ __ ___| |
# | |_) | |   | || |_  | / __| | '_ \ / _ \| __| / __|/ _ \/ __| | | | '__/ _ \ |
# |  _ <| |___|__   _| | \__ \ | | | | (_) | |_  \__ \  __/ (__| |_| | | |  __/_|
# |_| \_\\____|  |_|   |_|___/ |_| |_|\___/ \__| |___/\___|\___|\__,_|_|  \___(_)

class rc4():
    "A very simple but insecure random number generator"
    def __init__(self, key=""):
        self.S = list(range(256))
        if len(key) > 0:
            j = 0
            for i in range(256):
                key = map(ord, key)
                j = (j + self.S[i] + key[i % len(key)]) % 256
                self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def rand_int8(self):
        "return a psuedorandom integer mod 256"
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.S[self.i]) % 256
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        return self.S[(self.S[self.i] + self.S[self.j]) % 256]

    def rand_int16(self):
        "Combine two 8-bit random numbers into a 16 bit value"
        return (self.rand_int8()<<8)+(self.rand_int8())

    def rand_int32(self):
        "Combine two 16-bit random numbers into a 32 bit value"
        return (self.rand_int16()<<16)+(self.rand_int16())

    def rand(self):
        "Return a random float in the range 0-1"
        return float(self.rand_int32())/float(2**32)
