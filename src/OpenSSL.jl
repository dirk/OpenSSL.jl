# OpenSSL

VERSION >= v"0.4.0-dev+6521" && __precompile__()
module OpenSSL

  const LIBCRYPTO = ENV["OS"] == "Windows_NT" ? "libeay32" : "libcrypto"

  function init()
    # ccall((:OpenSSL_add_all_digests, OpenSSL.LIBCRYPTO), Void, ())
    # ccall((:OpenSSL_add_all_ciphers, OpenSSL.LIBCRYPTO), Void, ())
    # ccall((:OPENSSL_add_all_algorithms_conf, OpenSSL.LIBCRYPTO), Void, ())
    ccall((:OPENSSL_add_all_algorithms_noconf, OpenSSL.LIBCRYPTO), Void, ())
    # alias OpenSSL_add_all_algorithms :OPENSSL_add_all_algorithms_noconf
  end

  function cleanup()
    ccall((:EVP_cleanup, OpenSSL.LIBCRYPTO), Void, ())
  end

  module Digest
    import OpenSSL

    function init()
      ccall((:OpenSSL_add_all_digests, OpenSSL.LIBCRYPTO), Void, ())
    end

    function cleanup()
      ccall((:EVP_cleanup, OpenSSL.LIBCRYPTO), Void, ())
    end

    function digest(name::AbstractString, bs::Array{UInt8,1})
      ctx = ccall((:EVP_MD_CTX_create, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      try
        # Get the message digest struct
        md = ccall((:EVP_get_digestbyname, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), name)
        if(md == C_NULL)
          error("Unknown message digest $name")
        end
        # Add the digest struct to the context
        ccall((:EVP_DigestInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}), ctx, md, C_NULL)
        # Update the context with the input data : bs
        ccall((:EVP_DigestUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, UInt), ctx, bs, length(bs))
        # Figure out the size of the output string for the digest
        size = ccall((:EVP_MD_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), md)
        uval = Array(UInt8, size)
        # Calculate the digest and store it in the uval array
        ccall((:EVP_DigestFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ptr{UInt}), ctx, uval, C_NULL)
        return uval
      finally
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/digest

    function digestinit(name::AbstractString)
      ctx = ccall((:EVP_MD_CTX_create, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      try
        # Get the message digest struct
        md = ccall((:EVP_get_digestbyname, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), name)
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

    function digestupdate(ctx, bs::Array{UInt8,1})
      try
        # Update the context with the input data : bs
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
        return uval
      finally
        ccall((:EVP_MD_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/digestfinalize

  end#/Digest

  module Cipher
    import OpenSSL

    function init()
      ccall((:OpenSSL_add_all_ciphers, OpenSSL.LIBCRYPTO), Void, ())
    end

    function cleanup()
      ccall((:EVP_cleanup, OpenSSL.LIBCRYPTO), Void, ())
    end

    function encrypt(name::AbstractString, key::Array{UInt8,1}, iv::Array{UInt8,1}, plain::Array{UInt8,1})
      ctx = ccall((:EVP_CIPHER_CTX_new, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      ccall((:EVP_CIPHER_CTX_init, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      try
        enc = Array{UInt8,1}([])
        # ec = ccall((:EVP_get_cipherbyname, OpenSSL.LIBCRYPTO), Ptr{Void}, (Ptr{UInt8},), name)
        algorithm = Symbol("EVP_"*name)
        if(algorithm != :EVP_aes_256_cbc)
          error("Not support cipher algorithm $name")
        end
        # ec = ccall((algorithm, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
        ec = ccall((:EVP_aes_256_cbc, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
        if(ec == C_NULL)
          error("Unknown cipher algorithm $name")
        end
        ccall((:EVP_EncryptInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{UInt8}, Ptr{UInt8}), ctx, ec, C_NULL, key, iv)

        tmpenc = Array(UInt8, 16)
        tmplen = UInt(0)
        blksize = ccall((:EVP_CIPHER_CTX_block_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), ctx)

        ccall((:EVP_EncryptUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ptr{UInt}, Ptr{UInt8}, UInt), ctx, tmpenc, &tmplen, plain, blksize)
        enc = [enc; tmpenc]

        remain = 0
        if(length(plain) > 16) # if(remain > 0)
          ccall((:EVP_EncryptFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ptr{UInt}), ctx, tmpenc, &tmplen)
          enc = [enc; tmpenc]
        end

        ccall((:EVP_CIPHER_CTX_cleanup, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
        return enc
      finally
        ccall((:EVP_CIPHER_CTX_free, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/encrypt

    function decrypt(name::AbstractString, key::Array{UInt8,1}, iv::Array{UInt8,1}, bs::Array{UInt8,1})
      ctx = ccall((:EVP_CIPHER_CTX_create, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      try
      finally
        ccall((:EVP_CIPHER_CTX_destroy, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/decrypt

  end#/Cipher

end#/OpenSSL
