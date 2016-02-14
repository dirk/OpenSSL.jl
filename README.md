OpenSSL
==========

fork of [OpenSSL](https://github.com/dirk/OpenSSL.jl)

convert for julia 0.4-


# how to use it

```julia
import OpenSSL

OpenSSL.init()
s = OpenSSL.Digest.digest("SHA512", "test")
m = OpenSSL.Digest.digest("MD5", "test")
OpenSSL.cleanup()
```


# see also

[AES256CBC](https://github.com/HatsuneMiku/AES256CBC.jl)

```julia
# AES256CBC encrypt/decrypt
using AES256CBC
# typealias UBytes Array{UInt8, 1}
plain = string2bytes("Message") # UBytes
passwd = string2bytes("Secret Passphrase") # UBytes
salt = genRandUBytes(8) # UBytes
(key32, iv16) = genKey32Iv16(passwd, salt) # (UBytes, UBytes)
encoded = encryptAES256CBC(key32, iv16, plain) # UBytes
decoded = decryptAES256CBC(key32, iv16, encoded) # UBytes
```


# status

[![Build Status _dev_aes256cbc](https://travis-ci.org/HatsuneMiku/OpenSSL.jl.svg?branch=_dev_aes256cbc)](https://travis-ci.org/HatsuneMiku/OpenSSL.jl)

[![Build Status master](https://travis-ci.org/HatsuneMiku/OpenSSL.jl.svg?branch=master)](https://travis-ci.org/HatsuneMiku/OpenSSL.jl)
