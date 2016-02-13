# OpenSSL

VERSION >= v"0.4.0-dev+6521" && __precompile__()
module OpenSSL

  const LIBCRYPTO = ENV["OS"] == "Windows_NT" ? "libeay32" : "libcrypto"

  module Digest
    import OpenSSL

    function init()
      ccall((:OpenSSL_add_all_digests, OpenSSL.LIBCRYPTO), Void, ())
    end

    function cleanup()
      ccall((:EVP_cleanup, OpenSSL.LIBCRYPTO), Void, ())
    end

    function digest(name::AbstractString, data::AbstractString)
      ctx = ccall((:EVP_MD_CTX_create, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      try
        # Get the message digest struct
        md = ccall((:EVP_get_digestbyname, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), bytestring(name))
        if(md == C_NULL)
          error("Unknown message digest $name")
        end
        # Add the digest struct to the context
        ccall((:EVP_DigestInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}), ctx, md, C_NULL)
        # Update the context with the input data
        bs = bytestring(data)
        ccall((:EVP_DigestUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, UInt), ctx, bs, length(bs))
        # Figure out the size of the output string for the digest
        size = ccall((:EVP_MD_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), md)
        uval = Array(UInt8, size)
        # Calculate the digest and store it in the uval array
        ccall((:EVP_DigestFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ptr{UInt}), ctx, uval, C_NULL)
        # bytestring(uval)
        # Convert the uval array to a string of hexes
        return bytes2hex(uval)
      finally
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/digest

    function digestinit(name::AbstractString)
      ctx = ccall((:EVP_MD_CTX_create, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      try
        # Get the message digest struct
        md = ccall((:EVP_get_digestbyname, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), bytestring(name))
        if(md == C_NULL)
          error("Unknown message digest $name")
        end
        # Add the digest struct to the context
        ccall((:EVP_DigestInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}), ctx, md, C_NULL)
        # Update the context with the input data
        ctx
      catch
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
        nothing
      end
    end#/digestinit

    function digestupdate(ctx,data::AbstractString)
      try
        # Update the context with the input data
        bs = bytestring(data)
        ccall((:EVP_DigestUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, UInt), ctx, bs, length(bs))
        ctx
      catch
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
        nothing
      end
    end#/digestupdate

    function digestfinalize(ctx)
      try
        # Get the message digest struct
        md = ccall((:EVP_MD_CTX_md, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), ctx)
        if(md == C_NULL)
          error("Unknown message digest $name")
        end
        size = ccall((:EVP_MD_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), md)
        uval = Array(UInt8, size)
        # Calculate the digest and store it in the uval array
        ccall((:EVP_DigestFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ptr{UInt}), ctx, uval, C_NULL)
        # bytestring(uval)
        # Convert the uval array to a string of hexes
        return bytes2hex(uval)
      finally
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/digestfinalize

  end#/Digest

end#/OpenSSL
