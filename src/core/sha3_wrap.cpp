/*
 * sha3.h
 *
 *  Created on: Aug 31, 2018
 *  (c) 2018 array.io
 */

#include <eth-crypto/core/sha3_wrap.h>

namespace dev {

namespace openssl {

sha3_224_encoder::sha3_224_encoder()
  : sha3_encoder_base(EVP_sha3_224) {
  EVP_DigestInit_ex(ctx, EVP_sha3_224(), NULL);
}

sha3_224_encoder::~sha3_224_encoder() {}

sha3_256_encoder::sha3_256_encoder()
  : sha3_encoder_base(EVP_sha3_256) {
  EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
}

sha3_256_encoder::~sha3_256_encoder() {}

sha3_512_encoder::sha3_512_encoder()
  : sha3_encoder_base(EVP_sha3_512) {
  EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL);
}

sha3_512_encoder::~sha3_512_encoder() {}

bool sha3(bytesConstRef _input, bytesRef o_output) noexcept {
  if (o_output.size() != dev::h256::size)
    return false;
  sha3_256_encoder enc;
  enc.write((char *) _input.data(), _input.size());
  enc.result((char *) o_output.data(), o_output.size());
  return true;
}

bool sha3_512(bytesConstRef _input, bytesRef o_output) noexcept {
  if (o_output.size() != dev::h512::size)
    return false;
  sha3_512_encoder enc;
  enc.write((char *) _input.data(), _input.size());
  enc.result((char *) o_output.data(), o_output.size());
  return true;
}

}

/* https://github.com/ethereum/wiki/wiki/Ethash
 *
 * Ethereum's development coincided with the development of the SHA3 standard,
 * and the standards process made a late change in the padding of the finalized
 * hash algorithm, so that Ethereum's "sha3_256" and "sha3_512" hashes are not
 * standard sha3 hashes, but a variant often referred to as "Keccak-256" and
 * "Keccak-512" in other contexts.
 */
    namespace ethash{

        h256 sha3_ethash(bytes const &_input) {
            auto res = ethash_h256_t();
            SHA3_256(static_cast<const ethash_h256 *> (&res), _input.data(), _input.size());
            dev::FixedHash<32> hash((byte const *) &res.b[0],
                                    dev::FixedHash<32>::ConstructFromPointerType::ConstructFromPointer);
            return hash;
        }
    }
}


