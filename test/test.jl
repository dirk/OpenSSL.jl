import OpenSSL
using Base.Test

include("data.jl")

function string2bytes(s::AbstractString)
  return read(IOBuffer(s), UInt8, length(s))
end

@test isdefined(:OpenSSL) == true
OpenSSL.init()

s = OpenSSL.Digest.digest("SHA512", string2bytes("test"))
println(s)
@test s == sha512_of_test

m = OpenSSL.Digest.digest("MD5", string2bytes("test"))
println(m)
@test m == md5_of_test

h = OpenSSL.Digest.digest("MD5",
  hex2bytes("5365637265742050617373706872617365a3e550e89e70996c"))
println(h)
@test h == md5_of_bytes

es = OpenSSL.Cipher.encrypt("aes_256_cbc",
  hex2bytes("e299ff9d8e4831f07e5323913c53e5f0fec3a040a211d6562fa47607244d0051"),
  hex2bytes("7c7ed9434ddb9c2d1e1fcc38b4bf4667"),
  string2bytes("Message\t\t\t\t\t\t\t\t\t"))
println(es)
@test es == aes256cbc_of_shortdata

el = OpenSSL.Cipher.encrypt("aes_256_cbc",
  hex2bytes("e299ff9d8e4831f07e5323913c53e5f0fec3a040a211d6562fa47607244d0051"),
  hex2bytes("7c7ed9434ddb9c2d1e1fcc38b4bf4667"),
  string2bytes("Message\t\t\t\t\t\t\t\t\t\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"))
println(el)
@test el == aes256cbc_of_longdata

OpenSSL.cleanup()
println("All tests passed")
