#!/usr/bin/env python2

# __        ___    ____  _   _ ___ _   _  ____ _
# \ \      / / \  |  _ \| \ | |_ _| \ | |/ ___| |
#  \ \ /\ / / _ \ | |_) |  \| || ||  \| | |  _| |
#   \ V  V / ___ \|  _ <| |\  || || |\  | |_| |_|
#    \_/\_/_/   \_\_| \_\_| \_|___|_| \_|\____(_)

#  _   _  ___ _____   ____  _____ ____ _   _ ____  _____
# | \ | |/ _ \_   _| / ___|| ____/ ___| | | |  _ \| ____|
# |  \| | | | || |   \___ \|  _|| |   | | | | |_) |  _|
# | |\  | |_| || |    ___) | |__| |___| |_| |  _ <| |___
# |_| \_|\___/ |_|   |____/|_____\____|\___/|_| \_\_____|

# The current aes implementation in this library is *NOT* secure.

# 1. It uses (truncated or padded) raw keys instead of generating one
#    using a key-derivation function. Technically not fatal but can
#    easily allow in low entropy keys with incorrect use.

# 2. It is complete broken by side-channel attacks

import sys                      # builtin
import aes                      # my own aes implementation

if len(sys.argv)<2:
    sys.stderr.write("Usage %s KEY [-decrypt]"%argv[0])
    quit(1)

# add padding to ensure the key is at least
# then take first bytes in case the key is already more than 16 bytes
# *** THIS ALLOWS FOR LOW ENTRY KEY **
key = aes.add_PKCS7_padding(sys.argv[1],16)[:16]

if len(sys.argv)>2:             # lets assume any third argument is -decrypt
    ciphertext = sys.stdin.read()
    plaintext = aes.decrypt_128_cbc(ciphertext,key)
    sys.stdout.write(plaintext)
else:
    plaintext = sys.stdin.read()
    ciphertext = aes.encrypt_128_cbc(plaintext,key)
    sys.stdout.write(ciphertext)

