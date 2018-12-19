/*
 * sha3.h
 *
 *  Created on: Aug 31, 2018
 *  (c) 2018 array.io
 */
#pragma once

#include <cstdint>
#include <cstring>

#include <openssl/evp.h>

#include <../../eth-crypto/ethash/src/libethash/sha3.h>
#include <../../eth-crypto/ethash/src/libethash/ethash.h>

#include "FixedHash.h"

namespace dev
{

namespace openssl {

template<size_t N>
class sha3_encoder_base {
public:
  template<typename T>
  sha3_encoder_base(T p_evp_sha_func)
    :m_evp_sha_func(p_evp_sha_func) {
      ctx = EVP_MD_CTX_create();
  }
  
  using result_t = dev::FixedHash<N>;
  
  virtual ~sha3_encoder_base() {
      EVP_MD_CTX_destroy(ctx);
  }
  
  void write(const char *d, uint32_t dlen) {
      //TODO: implement error handling
      EVP_DigestUpdate(ctx, d, dlen);
  }
  
  void put(char c) {
      write(&c, 1);
  }
  
  result_t result() {
      result_t result;
      unsigned int digest_len;
      int sha_size = EVP_MD_size(m_evp_sha_func());
      if(result.size != sha_size)
        throw std::runtime_error("sha3_encoder_base::result(): Invalid sha3_256 hash size");
      
      EVP_DigestFinal_ex(ctx, result.data(), &digest_len);
    
      if(digest_len != result.size)
        throw std::runtime_error("sha3_encoder_base::result(): Invalid sha3_256 hash size has been written");
      
      return result;
  }
  
  void result(char *out, uint32_t dlen) {
      unsigned int digest_len;
      int sha_size = EVP_MD_size(m_evp_sha_func());
      if(dlen != sha_size)
        throw std::runtime_error("sha3_encoder_base::result(char, uint32_t): Invalid sha3_256 hash size");
      EVP_DigestFinal_ex(ctx, (unsigned char *) out, &digest_len);
      if(digest_len != dlen)
        throw std::runtime_error("sha3_encoder_base::result(char, uint32_t): Invalid sha3_256 hash size has been written");
  }

protected:
  EVP_MD_CTX *ctx;
  std::function<const EVP_MD *(void)> m_evp_sha_func;
};

class sha3_224_encoder : public sha3_encoder_base<28> {
public:
  sha3_224_encoder();
  
  virtual ~sha3_224_encoder();
};

class sha3_256_encoder : public sha3_encoder_base<32> {
public:
  sha3_256_encoder();
  
  virtual ~sha3_256_encoder();
};

class sha3_512_encoder : public sha3_encoder_base<64> {
public:
  sha3_512_encoder();
  
  virtual ~sha3_512_encoder();
};

// SHA-3 convenience routines.

/// Calculate SHA3-256 hash of the given input and load it into the given output.
/// @returns false if o_output.size() != 32.
bool sha3(bytesConstRef _input, bytesRef o_output) noexcept;

/// Calculate SHA3-512 hash of the given input and load it into the given output.
/// @returns false if o_output.size() != 32.
bool sha3_512(bytesConstRef _input, bytesRef o_output) noexcept;

inline h512 sha3_512(bytesConstRef _input) noexcept {
    h512 ret;
    sha3_512(_input, ret.ref());
    return ret;
}

/// Calculate SHA3-256 hash of the given input (presented as a binary-filled string), returning as a 256-bit hash.
inline h512 sha3_512(std::string const &_input) noexcept {
    return sha3_512(bytesConstRef(_input));
}

template<unsigned N>
inline h512 sha3_512(FixedHash<N> const &_input) noexcept {
    return sha3_512(_input.ref());
}

/// Calculate SHA3-256 hash of the given input, returning as a 256-bit hash.
inline h256 sha3(bytesConstRef _input) noexcept {
    h256 ret;
    sha3(_input, ret.ref());
    return ret;
}

inline SecureFixedHash<32> sha3Secure(bytesConstRef _input) noexcept {
    SecureFixedHash<32> ret;
    sha3(_input, ret.writable().ref());
    return ret;
}

/// Calculate SHA3-256 hash of the given input, returning as a 256-bit hash.
inline h256 sha3(bytes const &_input) noexcept {
    return sha3(bytesConstRef(&_input));
}

inline SecureFixedHash<32> sha3Secure(bytes const &_input) noexcept {
    return sha3Secure(bytesConstRef(&_input));
}

/// Calculate SHA3-256 hash of the given input (presented as a binary-filled string), returning as a 256-bit hash.
inline h256 sha3(std::string const &_input) noexcept {
    return sha3(bytesConstRef(_input));
}

inline SecureFixedHash<32> sha3Secure(std::string const &_input) noexcept {
    return sha3Secure(bytesConstRef(_input));
}

/// Calculate SHA3-256 hash of the given input (presented as a FixedHash), returns a 256-bit hash.
template<unsigned N>
inline h256 sha3(FixedHash<N> const &_input) noexcept {
    return sha3(_input.ref());
}

template<unsigned N>
inline SecureFixedHash<32> sha3Secure(FixedHash<N> const &_input) noexcept {
    return sha3Secure(_input.ref());
}

/// Fully secure variants are equivalent for sha3 and sha3Secure.
inline SecureFixedHash<32> sha3(bytesSec const &_input) noexcept {
    return sha3Secure(_input.ref());
}

inline SecureFixedHash<32> sha3Secure(bytesSec const &_input) noexcept {
    return sha3Secure(_input.ref());
}

template<unsigned N>
inline SecureFixedHash<32> sha3(SecureFixedHash<N> const &_input) noexcept {
    return sha3Secure(_input.ref());
}

template<unsigned N>
inline SecureFixedHash<32> sha3Secure(SecureFixedHash<N> const &_input) noexcept {
    return sha3Secure(_input.ref());
}

}

namespace ethash
{

h256 sha3_ethash(bytes const &_input);

template<unsigned N>
h256 sha3_ethash(FixedHash<N> const &_input) {
    auto res = ethash_h256_t();
    SHA3_256(static_cast<const ethash_h256 *> (&res), _input.data(), N);
    dev::FixedHash<32> hash((byte const *) &res.b[0],
                            dev::FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
    return hash;
}

};

}

namespace fc
{

class variant;
void to_variant( const dev::h256& bi, variant& v );
void from_variant( const variant& v, dev::h256& bi );

}
