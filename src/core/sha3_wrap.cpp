/*
 * sha3.h
 *
 *  Created on: Aug 31, 2018
 *  (c) 2018 array.io
 */

#include <eth-crypto/core/sha3_wrap.h>

namespace dev {
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


