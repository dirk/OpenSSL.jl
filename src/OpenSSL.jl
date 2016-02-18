# OpenSSL

VERSION >= v"0.4.0-dev+6521" && __precompile__()
module OpenSSL

  const LIBCRYPTO = @windows ? "libeay32" : "libcrypto"

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
        ccall((:EVP_DigestUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, UInt), ctx, bs, sizeof(bs))
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
        ccall((:EVP_DigestUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, UInt), ctx, bs, sizeof(bs))
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

    function get_EVP_CIPHER(name::AbstractString)
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
      return ec
    end

    function encrypt(name::AbstractString, key::Array{UInt8,1}, iv::Array{UInt8,1}, plain::Array{UInt8,1}, selfpad::Bool=false)
      ctx = ccall((:EVP_CIPHER_CTX_new, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      ccall((:EVP_CIPHER_CTX_init, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      try
        ec = get_EVP_CIPHER(name)
        ccall((:EVP_EncryptInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{UInt8}, Ptr{UInt8}), ctx, ec, C_NULL, key, iv)

        # :EVP_CIPHER_CTX_block_size must be after :EVP_EncryptInit_ex
        blksize = ccall((:EVP_CIPHER_CTX_block_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), ctx)
        if(selfpad)
          ccall((:EVP_CIPHER_CTX_set_padding, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void}, UInt), ctx, 0) # disable
        end
        remain = sizeof(plain) % blksize
        padlen = blksize - remain
        enclen = sizeof(plain) + padlen
        enc = Array(UInt8, enclen)
        outlen = UInt(1) # start position = 1
        tmpenc = Array(UInt8, blksize)
        tmplen = Ref{Cint}(0)

        for i in 1:div(sizeof(plain), blksize)
          ccall((:EVP_EncryptUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, UInt), ctx, tmpenc, tmplen, plain[outlen:outlen+blksize-1], blksize)
          if(tmplen[] > 0) enc[outlen:outlen+blksize-1] = tmpenc[1:blksize] end
          outlen += tmplen[]
        end

        if(remain > 0)
          ccall((:EVP_EncryptUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, UInt), ctx, tmpenc, tmplen, plain[outlen:outlen+remain-1], remain)
          if(tmplen[] > 0) enc[outlen:outlen+remain-1] = tmpenc[1:remain] end
          outlen += tmplen[]
        end

        if(selfpad && padlen != 0) # no use (padlen > 0), UInt is everytime > 0
          # skip
          # outlen += tmplen[]
        end

        if(!selfpad)
          ccall((:EVP_EncryptFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ref{Cint}), ctx, tmpenc, tmplen)
          if(tmplen[] > 0) enc[outlen:outlen+blksize-1] = tmpenc[1:blksize] end
          outlen += tmplen[]
        end

        ccall((:EVP_CIPHER_CTX_cleanup, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
        return enc
      finally
        ccall((:EVP_CIPHER_CTX_free, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/encrypt

    function decrypt(name::AbstractString, key::Array{UInt8,1}, iv::Array{UInt8,1}, cipher::Array{UInt8,1}, selfpad::Bool=false)
      ctx = ccall((:EVP_CIPHER_CTX_new, OpenSSL.LIBCRYPTO), Ptr{Void}, ())
      ccall((:EVP_CIPHER_CTX_init, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      try
        ec = get_EVP_CIPHER(name)
        ccall((:EVP_DecryptInit_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{UInt8}, Ptr{UInt8}), ctx, ec, C_NULL, key, iv)

        # :EVP_CIPHER_CTX_block_size must be after :EVP_DecryptInit_ex
        blksize = ccall((:EVP_CIPHER_CTX_block_size, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void},), ctx)
        if(selfpad)
          ccall((:EVP_CIPHER_CTX_set_padding, OpenSSL.LIBCRYPTO), UInt, (Ptr{Void}, UInt), ctx, 0) # disable
        end
        declen = sizeof(cipher) # trim padlen later
        dec = Array(UInt8, declen)
        outlen = UInt(1) # start position = 1
        tmpdec = Array(UInt8, blksize)
        tmplen = Ref{Cint}(0)

        for i in 1:div(sizeof(cipher), blksize)
          ccall((:EVP_DecryptUpdate, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, UInt), ctx, tmpdec, tmplen, cipher[outlen:outlen+blksize-1], blksize)
          if(tmplen[] > 0) dec[outlen:outlen+blksize-1] = tmpdec[1:blksize] end
          outlen += tmplen[]
        end

        if(!selfpad)
          ccall((:EVP_DecryptFinal_ex, OpenSSL.LIBCRYPTO), Void, (Ptr{Void}, Ptr{UInt8}, Ref{Cint}), ctx, tmpdec, tmplen)
          if(tmplen[] > 0) dec[outlen:outlen+blksize-1] = tmpdec[1:blksize] end
          outlen += tmplen[]
        end

        ccall((:EVP_CIPHER_CTX_cleanup, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
        return selfpad ? dec[1:declen-dec[declen]] : dec[1:outlen-1]
      finally
        ccall((:EVP_CIPHER_CTX_free, OpenSSL.LIBCRYPTO), Void, (Ptr{Void},), ctx)
      end
    end#/decrypt

  end#/Cipher

end#/OpenSSL
