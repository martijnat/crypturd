import common,aes,rc4,pkcs7

# Default encryption AES
encrypt = aes.encrypt
decrypt = aes.encrypt

# Default hash
hash = sha.sha256

# Default rng: rc4
# TODO: implement csrng
rand = rc4.rc4().rand