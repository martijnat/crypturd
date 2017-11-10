# USE AT YOUR OWN RISK

***Some implementations are likely vulnerable to side-channel attacks.***
Use with caution.

# mcrypto

Implementation of several cryptographic primitives.

![Screenshot](screenshot.png)

# Example usage

    import mcrypto

    plaintext = "Attack at dawn"
    key = "Random password."
    ciphertext = mcrypto.encrypt(plaintext,key) # use a default mode and block size (256-ctr in this case)

# Block ciphers

- AES (128/256 bit) (ECB/CBC/CTR) (SHA256-HMAC)

# Hash algorithms

- SHA256
- SHA256-HMAC

# Random number generators

- AES-128-CTR
- RC4 (cryptographically insecure RNG)

# Padding schemes

- Null Padding
- PKCS7


