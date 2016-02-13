import OpenSSL
using Base.Test

include("data.jl")

function string2bytes(s::AbstractString)
  return read(IOBuffer(s), UInt8, length(s))
end

@test isdefined(:OpenSSL) == true
OpenSSL.Digest.init()

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

OpenSSL.Digest.cleanup()
println("All tests passed")
