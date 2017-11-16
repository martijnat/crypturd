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

import mcrypto.aes
import mcrypto.common
import mcrypto.default
import mcrypto.md4
import mcrypto.mt19937
import mcrypto.pkcs7
import mcrypto.rc4
import mcrypto.sha
import os

# Speed up this module at the cost of revealing our secret keys
# through side channel attacks. Since these are just tests with random
# keys, this is not a problem.
mcrypto.common.ctlt = False


def test_generic_hash(alg, message, h):
    if mcrypto.common.hexstr(alg(message)) != h:
        print("Algorithm %s" % repr(alg))
        print("Message   %s" % repr(message))
        print("Expected  %s" % repr(h))
        print("Got       %s" % repr(mcrypto.common.hexstr(alg(message))))
        quit(1)
        # print("(%s, %s),"%(repr(message),repr(mcrypto.common.hexstr(alg(message)))))


def test_aes():
    # Test primitives with null-data and null-key
    for alg, result in [(
        mcrypto.aes.aes128enc, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
            (mcrypto.aes.aes128dec, "140f0f1011b5223d79587717ffd9ec3a")]:
        assert mcrypto.common.hexstr(alg("\0" * 16, "\0" * 16)) == result

    for alg, result in [(
        mcrypto.aes.aes256enc, "a7d13a59e9d87506d2f7f8f4ada2b43e"),
            (mcrypto.aes.aes256dec, "32436508ae6e02d815de45d4910d711b")]:
        assert mcrypto.common.hexstr(alg("\0" * 16, "\0" * 32)) == result

    # Test all mode with random data and random keys
    for key in [os.urandom(i) for i in [0, 5, 16, 32, 33]]:
        for plaintext in [os.urandom(j) for j in [0, 16, 32, 33, 1000]]:
            for enc, dec in [(
                mcrypto.aes.encrypt_128_ecb, mcrypto.aes.decrypt_128_ecb),
                (mcrypto.aes.encrypt_128_cbc,
                 mcrypto.aes.decrypt_128_cbc),
                            (mcrypto.aes.encrypt_128_ctr,
                             mcrypto.aes.decrypt_128_ctr),
                            (mcrypto.aes.encrypt_256_ecb,
                             mcrypto.aes.decrypt_256_ecb),
                            (mcrypto.aes.encrypt_256_cbc,
                             mcrypto.aes.decrypt_256_cbc),
                            (mcrypto.aes.encrypt_256_ctr, mcrypto.aes.decrypt_256_ctr), ]:
                ciphertext = enc(plaintext, key)
                assert ciphertext != plaintext
                assert dec(ciphertext, key) == plaintext


def test_default():
    # check that encryption/decryption works
    random_data = os.urandom(256)
    random_key = os.urandom(51)
    ciphertext = mcrypto.default.encrypt(random_data, random_key)
    plaintext = mcrypto.default.decrypt(ciphertext, random_key)
    assert random_data == plaintext

    for _ in range(1000):
        # check that values are in the range 0.0-1.0
        assert abs(mcrypto.default.rand() - 0.5) <= 0.5

    # check that all hashes have the same length
    hlens = [len(mcrypto.default.hash(os.urandom(ord(os.urandom(1)))))
             for _ in range(1000)]
    assert min(hlens) > 0
    assert min(hlens) == max(hlens)


def test_md4():
    for m, h in [("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
                 ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
                 ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
                 ("message digest", "d9130a8164549fe818874806e1c7014b"),
                 ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
                 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"),
                 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"), ]:
        test_generic_hash(mcrypto.md4.md4, m, h)


def test_mt19937():
    orig = mcrypto.mt19937.mt19937(ord(os.urandom(1)))
    for _ in range(1248):
        # check that all outputs are in the range 0.0-1.0
        assert abs(orig.rand() - 0.5) <= 0.5

    # check that we can clone an instance
    outputs = [orig.rand_int32() for _ in range(624)]
    clone = mcrypto.mt19937.mt19937_Clone(outputs)
    for i in range(1248):
        assert orig.rand() == clone.rand()


def test_pkcs7():
    for dlength in range(2, 100):
        for plength in range(2, 100):
            data = os.urandom(dlength)
            assert mcrypto.pkcs7.remove_padding(
                mcrypto.pkcs7.add_padding(data, plength)) == data


def test_rc4():
    r = mcrypto.rc4.rc4().rand
    for _ in range(1000):
        # check that all outputs are in the range 0.0-1.0
        assert abs(r() - 0.5) <= 0.5


def test_sha():
    for m, h in [('', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
                 ('a', '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8'),
                 ('abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'),
                 ('message digest', 'c12252ceda8be8994d5fa0290a47231c1d16aae3'),
                 ('abcdefghijklmnopqrstuvwxyz', '32d10c7b8cf96570ca04ce37f2a19d84240d3a89'),
                 ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', '761c457bf73b14d27e9e9265c46f4b4dda11f940'),
                 ('12345678901234567890123456789012345678901234567890123456789012345678901234567890', '50abf5706a150990a08b2c5ea40fa0e585554732'),]:
        test_generic_hash(mcrypto.sha.sha1, m, h)

    for m, h in [('a', 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'),
                 ('abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
                 ('message digest', 'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650'),
                 ('abcdefghijklmnopqrstuvwxyz', '71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73'),
                 ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0'),
                 ('12345678901234567890123456789012345678901234567890123456789012345678901234567890', 'f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e'),]:
        test_generic_hash(mcrypto.sha.sha256, m, h)

def test_all():
    test_aes()
    test_default()
    test_md4()
    test_mt19937()
    test_pkcs7()
    test_rc4()
    test_sha()
