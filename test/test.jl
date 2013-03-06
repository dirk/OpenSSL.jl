require("OpenSSL")

include("data.jl")

assert(isdefined(:OpenSSL))
OpenSSL.Digest.init()

assert(OpenSSL.Digest.digest("SHA512", "test") == sha512_of_test)
assert(OpenSSL.Digest.digest("MD5", "test") == md5_of_test)

OpenSSL.Digest.cleanup()
println("All tests passed")
