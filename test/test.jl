import OpenSSL
using Base.Test

include("data.jl")

@test isdefined(:OpenSSL) == true
OpenSSL.Digest.init()

@test OpenSSL.Digest.digest("SHA512", "test") == sha512_of_test
@test OpenSSL.Digest.digest("MD5", "test") == md5_of_test

OpenSSL.Digest.cleanup()
println("All tests passed")
