import OpenSSL
using Base.Test

include("data.jl")

@test isdefined(:OpenSSL) == true
OpenSSL.init()

s = OpenSSL.Digest.digest("SHA512", "test".data)
println(s)
@test s == sha512_of_test

m = OpenSSL.Digest.digest("MD5", "test".data)
println(m)
@test m == md5_of_test

h = OpenSSL.Digest.digest("MD5",
  hex2bytes("5365637265742050617373706872617365a3e550e89e70996c"))
println(h)
@test h == md5_of_bytes

key32 = hex2bytes("e299ff9d8e4831f07e5323913c53e5f0"*
                  "fec3a040a211d6562fa47607244d0051")
iv16 = hex2bytes("7c7ed9434ddb9c2d1e1fcc38b4bf4667")

### selfpad=true
#plainshort = "Message\t\t\t\t\t\t\t\t\t".data
#plainlong = "Message\t\t\t\t\t\t\t\t\t"*
#  "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10".data

### selfpad=false
plainshort = "Message".data
plainlong = "Message\t\t\t\t\t\t\t\t\t".data

es = OpenSSL.Cipher.encrypt("aes_256_cbc", key32, iv16, plainshort)
println(es)
@test es == aes256cbc_of_shortdata

ds = OpenSSL.Cipher.decrypt("aes_256_cbc", key32, iv16, es)
println(ds)
@test ds == plainshort

el = OpenSSL.Cipher.encrypt("aes_256_cbc", key32, iv16, plainlong)
println(el)
@test el == aes256cbc_of_longdata

dl = OpenSSL.Cipher.decrypt("aes_256_cbc", key32, iv16, el)
println(dl)
@test dl == plainlong

OpenSSL.cleanup()
println("All tests passed")
