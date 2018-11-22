/*
 * sha3.h
 *
 *  Created on: Aug 31, 2018
 *  (c) 2018 array.io
 */

#pragma once

#include "FixedHash.h"

#include <cstdint>
#include <cstring>

#include <openssl/evp.h>


#include <../../eth-crypto/ethash/src/libethash/sha3.h>
#include <../../eth-crypto/ethash/src/libethash/ethash.h>

namespace dev
{
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
