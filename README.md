# mcrypto

Some crypto implementations for testing attacks.

![Screenshot](screenshot.png)

This implementation is python2 only due to the way python3 handles
strings.

*** NOT SECURE, DO NOT USE FOR ANYTHING YOU CARE ABOUT ***

The current AES implementation in this library is *NOT* secure.

1. It uses (truncated or padded) raw keys instead of generating one
   using a key-derivation function. Technically not fatal but can
   easily allow in low entropy keys with incorrect use.

2. It is complete broken by side-channel attacks

# Example usage

    import mcrypto

    plaintext = "Attack at dawn"
    key = "Random password."
    ciphertext = mcrypto.encrypt(plaintext,key) # use a default mode and block size (256-ctr in this case)

# Block ciphers

- AES-128-CBC
- AES-128-ECB
- AES-128-CTR
- AES-256-CBC
- AES-256-ECB
- AES-256-CTR

# Hash algorithms

- SHA256

# Padding schemes

- PKCS7

# Random number generators

- RC4
