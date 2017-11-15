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
                 ("message digest",
                 "d9130a8164549fe818874806e1c7014b"),
                 ("abcdefghijklmnopqrstuvwxyz",
                 "d79e1c308aa5bbcdeea8ed63df412da9"),
                 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "043f8582f241db351ce627e153e7f0e4"),
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
    for m, h in [(
        "a", "3c2d41aa9279b007ade1453e120d614a96b8ad5a"),
        ("abc",
         "ffc36030cd405c2dfd8be8ab34e4ded35c034af8"),
                ("message digest",
                 "9c09beb6b841f7426c87af4d47b89f69af4a5963"),
                ("abcdefghijklmnopqrstuvwxyz",
                 "d231b3ca7af9f7faf63384507d4c1fb07100030e"),
                ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "436bf69bc979e0e3715ea6c07ddd06e21e0e0266"),
                ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "336f15390e38d46c76fdc30615470c7762bdf57b"), ]:
        test_generic_hash(mcrypto.sha.sha1, m, h)

    for m, h in [(
        "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("a",
         "08875e3d41314bd1dc2b2db5e4f4dd046bf3ec2799403457ae6e9f4e9d393422"),
                ("abc",
                 "203b1d9016060802fe5ef80436611159de1868b58d44940e3d3979eab5f4d193"),
                ("message digest",
                 "aecda3d80ba187cd6b8e4dab624fb7021d78f33eeffa04e0b99698f9159873f9"),
                ("abcdefghijklmnopqrstuvwxyz",
                 "2afe1f492b4cd70c8663a30b3439a462d2f6528b4eee2aa4111a3ecbb66eeb98"),
                ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                 "909702a2ce4818c42270f35d2d2d052dcce86382abd1f18d3f37435db2b6851e"),
                ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "1c8ea23470bb4891e4a9c9a577150ca74ef40de502d4e9437948e30f100214fb"), ]:
        test_generic_hash(mcrypto.sha.sha256, m, h)


def test_all():
    test_aes()
    test_default()
    test_md4()
    test_mt19937()
    test_pkcs7()
    test_rc4()
    test_sha()
