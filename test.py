#!/usr/bin/env python2

# Copyright (C) 2017  Martijn Terpstra

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Module for testing all other modules

import crypturd
import os
import sys
import time

def t_format_part(unit,n,l):
    if n>0:
        fstr = "%%%ii%s "%(l,unit)
        return fstr%(n)
    else:
        return ""

def t_format(t):
    if t<1.0:
        return " 0s "
    seconds = int(t%60)
    minutes = int((t//60)%60)
    hours   = int(t//3600)
    return "%s%s%s"%(t_format_part("h",hours,2),
                     t_format_part("m",minutes,2),
                     t_format_part("s",seconds,2))

def format_bytes_per_second(t,b):
    bps = b/t
    if bps>(1000**2):
        return "%6s MB/s"%round(bps/(1000**2),2)
    elif bps>1000:
        return "%6s KB/s"%round(bps/(1000),2)
    else:
        return "%6s   B/s"%round(bps,2)

def test_generic_hash(alg, message, h):
    if crypturd.common.hexstr(alg(message)) != h:
        print("Algorithm %s" % repr(alg))
        print("Message   %s" % repr(message))
        print("Expected  %s" % repr(h))
        print("Got       %s" % repr(crypturd.common.hexstr(alg(message))))
        quit(1)

def test_aes():
    bytes_processed = 0
    # Test primitives with null-data and null-key
    for alg, result in [(
        crypturd.aes.aes128enc, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
            (crypturd.aes.aes128dec, "140f0f1011b5223d79587717ffd9ec3a")]:
        assert crypturd.common.hexstr(alg("\0" * 16, "\0" * 16)) == result
        bytes_processed += 16

    for alg, result in [(
        crypturd.aes.aes256enc, "a7d13a59e9d87506d2f7f8f4ada2b43e"),
            (crypturd.aes.aes256dec, "32436508ae6e02d815de45d4910d711b")]:
        assert crypturd.common.hexstr(alg("\0" * 16, "\0" * 32)) == result
        bytes_processed += 16

    # Test all mode with random data and random keys
    for _ in range(10):
        for key in [os.urandom(i) for i in [0, 5, 16, 32, 33]]:
            for plaintext in [os.urandom(j) for j in [0, 16, 32, 33, 1000]]:
                for enc, dec in [(
                    crypturd.aes.encrypt_128_ecb, crypturd.aes.decrypt_128_ecb),
                    (crypturd.aes.encrypt_128_cbc,
                     crypturd.aes.decrypt_128_cbc),
                                (crypturd.aes.encrypt_128_ctr,
                                 crypturd.aes.decrypt_128_ctr),
                                (crypturd.aes.encrypt_256_ecb,
                                 crypturd.aes.decrypt_256_ecb),
                                (crypturd.aes.encrypt_256_cbc,
                                 crypturd.aes.decrypt_256_cbc),
                                (crypturd.aes.encrypt_256_ctr, crypturd.aes.decrypt_256_ctr), ]:
                    ciphertext = enc(plaintext, key)
                    assert ciphertext != plaintext
                    assert dec(ciphertext, key) == plaintext
                    bytes_processed += len(plaintext)*2
    return bytes_processed

def test_chacha20():
    bytes_processed = 0
    key = [0x03020100,  0x07060504,  0x0b0a0908,  0x0f0e0d0c,
           0x13121110,  0x17161514,  0x1b1a1918,  0x1f1e1d1c,]
    counter = [0x00000001,]
    nonce = [0x09000000,  0x4a000000,  0x00000000,]
    ciphertext = crypturd.chacha20.chacha20_block(key,counter,nonce)
    ref = ('10f1e7e4d13b5915500fdd1fa32071c4'
           +'c7d1f4c733c068030422aa9ac3d46c4e'
           +'d2826446079faa0914c2d705d98b02a2'
           +'b5129cd1de164eb9cbd083e8a2503c4e')
    assert crypturd.hexstr(ciphertext) == ref
    bytes_processed+=64
    for _ in range(500):
        for key in [os.urandom(i) for i in [0, 5, 16, 32, 33]]:
            for plaintext in [os.urandom(j) for j in [0, 16, 32, 33, 1000]]:
                assert crypturd.chacha20_decrypt(crypturd.chacha20_encrypt(plaintext,key),key) == plaintext
                bytes_processed+=len(plaintext)*2
    return bytes_processed


def test_default():
    bytes_processed = 0
    # check that encryption/decryption works
    random_data = os.urandom(256)
    random_key = os.urandom(51)
    ciphertext = crypturd.default.encrypt(random_data, random_key)
    plaintext = crypturd.default.decrypt(ciphertext, random_key)
    assert random_data == plaintext
    bytes_processed+=len(plaintext) + len(random_data)

    for _ in range(1000):
        # check that values are in the range 0.0-1.0
        assert abs(crypturd.default.rand() - 0.5) <= 0.5
        bytes_processed+=1

    # check that all hashes have the same length
    hlens = [len(crypturd.default.hash(os.urandom(ord(os.urandom(1)))))
             for _ in range(1000)]
    assert min(hlens) > 0
    assert min(hlens) == max(hlens)
    bytes_processed += len(hlens)*hlens[0]
    return bytes_processed

def test_dsa():
    bytes_processed = 0
    privkey = crypturd.dsa.DSAKey()
    pubkey = privkey.public()
    for _ in range(100):
        plaintext = os.urandom(8)
        sig = privkey.sign(plaintext)
        assert pubkey.verify(plaintext,sig)
        bytes_processed += 8
    return bytes_processed

def test_hsig():
    bytes_processed = 0
    pk,sk = crypturd.hsig.new_keys()
    for _ in range(10):
        data = os.urandom(32)
        new_pk,new_sk,sig = crypturd.hsig.full_step(data,sk)
        assert crypturd.hsig.verify(data,new_pk,sig,pk)
        assert not crypturd.hsig.verify(os.urandom(32),new_pk,sig,pk)
        bytes_processed+=128
    return bytes_processed

def test_md4():
    bytes_processed = 0
    for m, h in [("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
                 ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
                 ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
                 ("message digest", "d9130a8164549fe818874806e1c7014b"),
                 ("abcdefghijklmnopqrstuvwxyz",
                  "d79e1c308aa5bbcdeea8ed63df412da9"),
                 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                  "043f8582f241db351ce627e153e7f0e4"),
                 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"), ]:
        test_generic_hash(crypturd.md4, m, h)
        bytes_processed += len(m)

    return bytes_processed


def test_mt19937():
    bytes_processed = 0
    orig = crypturd.mt19937(ord(os.urandom(1)))
    for _ in range(1248):
        # check that all outputs are in the range 0.0-1.0
        assert abs(orig.rand() - 0.5) <= 0.5
        bytes_processed+=1

    # check that we can clone an instance
    outputs = [orig.rand_int32() for _ in range(624)]
    bytes_processed+=624
    clone = crypturd.mt19937_Clone(outputs)
    for i in range(1248):
        assert orig.rand() == clone.rand()
        bytes_processed+=1

    return bytes_processed


def test_pkcs7():
    bytes_processed = 0
    for dlength in range(2, 100):
        for plength in range(2, 100):
            data = os.urandom(dlength)
            with_padding = crypturd.pkcs7.add_padding(data, plength)
            assert crypturd.pkcs7.remove_padding(with_padding) == data
            bytes_processed +=  len(data)
            bytes_processed +=  len(with_padding)

    return bytes_processed


def test_rsa():
    bytes_processed = 0
    pubkey,privkey = crypturd.rsa.gen_public_private_key_pair(1024)
    for _ in range(100):
        rsa_plaintext = os.urandom(16)
        c = pubkey.encrypt(rsa_plaintext)
        sig = privkey.sign(rsa_plaintext)
        assert crypturd.common.littleendian2int(rsa_plaintext) == crypturd.common.littleendian2int(privkey.decrypt(c))
        assert pubkey.verify(rsa_plaintext,sig)
        bytes_processed += len(c)
        bytes_processed += len(sig)

    return bytes_processed


def test_rc4():
    bytes_processed = 0
    r = crypturd.rc4_rand().rand
    for _ in range(1000):
        # check that all outputs are in the range 0.0-1.0
        assert abs(r() - 0.5) <= 0.5
        bytes_processed +=1
    for _ in range(10):
        for key in [os.urandom(i) for i in [2, 5, 16, 32, 33]]:
            for plaintext in [os.urandom(j) for j in [2, 16, 32, 33, 1000]]:
                ciphertext = crypturd.rc4_encrypt(plaintext, key)
                assert ciphertext != plaintext
                assert crypturd.rc4_decrypt(ciphertext, key) == plaintext
                bytes_processed += len(plaintext)*2
    return bytes_processed


def test_sha():
    bytes_processed = 0
    for m, h in [('', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
                 ('a', '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8'),
                 ('abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'),
                 ('message digest',
                  'c12252ceda8be8994d5fa0290a47231c1d16aae3'),
                 ('abcdefghijklmnopqrstuvwxyz',
                  '32d10c7b8cf96570ca04ce37f2a19d84240d3a89'),
                 ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                  '761c457bf73b14d27e9e9265c46f4b4dda11f940'),
                 ('12345678901234567890123456789012345678901234567890123456789012345678901234567890', '50abf5706a150990a08b2c5ea40fa0e585554732'), ]:
        test_generic_hash(crypturd.sha.sha1, m, h)
        bytes_processed += len(m)

    for m, h in [(
        'a', 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'),
        ('abc',
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
                 ('message digest',
                  'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650'),
                 ('abcdefghijklmnopqrstuvwxyz',
                  '71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73'),
                 ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                  'db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0'),
                 ('12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e'), ]:
        test_generic_hash(crypturd.sha.sha256, m, h)
        bytes_processed += len(m)
    return bytes_processed


def test_all():
    # Speed up this module at the cost of revealing our secret keys
    # through side channel attacks. Since these are just tests with random
    # keys, this is not a problem.
    crypturd.common.ctlt = False

    # Show all exceptions
    crypturd.common.DEBUG = True

    t_0 = time.time()
    for test in [test_aes,
                 test_chacha20,
                 test_default,
                 test_dsa,
                 test_hsig,
                 test_md4,
                 test_mt19937,
                 test_pkcs7,
                 test_rc4,
                 test_rsa,
                 test_sha,]:
        try:
            sys.stdout.write("%20s: "%test.__name__)
            sys.stdout.flush()
            t_before = time.time()
            bytes_processed = test()
            t_after = time.time()
            sys.stdout.write("[ \033[32;1mOK\033[0m ]") # pretty green text
            sys.stdout.write(t_format(t_after-t_before))
            sys.stdout.write(format_bytes_per_second((t_after-t_before),bytes_processed))
        finally:
            sys.stdout.write("\n")
    t_end = time.time()
    sys.stdout.write("Total time: "+(t_format(t_end-t_0))+"\n")

    # Reset variables
    crypturd.common.ctlt = True
    crypturd.common.DEBUG = False
