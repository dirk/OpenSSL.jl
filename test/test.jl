import OpenSSL
using Base.Test

include("data.jl")

@test isdefined(:OpenSSL) == true
OpenSSL.Digest.init()

s = OpenSSL.Digest.digest("SHA512", "test")
println(s)
@test s == sha512_of_test

m = OpenSSL.Digest.digest("MD5", "test")
println(m)
@test m == md5_of_test

OpenSSL.Digest.cleanup()
println("All tests passed")
