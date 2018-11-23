/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file TransactionBase.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <eth-crypto/core/vector_ref.h>
//#include <libdevcore/Log.h>
#include <eth-crypto/core/Common.h>
#include <eth-crypto/core/Exceptions.h>
#include <eth-crypto/core/TransactionBase.h>
//#include "EVMSchedule.h"

using namespace std;
using namespace dev;
using namespace dev::eth;


void TransactionBase::sign(Secret const& _priv)
{
	auto sig = dev::sign(_priv, sha3(WithoutSignature));
	SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
	if (sigStruct.isValid())
		m_vrs = sigStruct;
}

void TransactionBase::streamRLP(RLPStream& _s, IncludeSignature _sig, bool _forEip155hash) const
{
	if (m_type == NullTransaction)
		return;

	_s.appendList((_sig || _forEip155hash ? 3 : 0) + 6);
	_s << m_nonce;
	_s << m_gasPrice;
	_s << m_gas;
	if (m_type == MessageCall)
		_s << m_receiveAddress;
	else
		_s << "";
	_s << m_value ;
	_s << m_data;

	if (_sig)
	{
//		if (!m_vrs)
//			BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

		if (hasZeroSignature())
			_s << m_chainId;
		else
		{
			int const vOffset = m_chainId * 2 + 35;
			_s << (m_vrs->v + vOffset);
		}
		_s << (u256)m_vrs->r << (u256)m_vrs->s;
	}
	else if (_forEip155hash)
	{
		_s << m_chainId;
		_s << 0;
		_s << 0;
	}
		//_s << m_chainId << 0 << 0;

}

static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");



h256 TransactionBase::sha3(IncludeSignature _sig) const
{
	if (_sig == WithSignature && m_hashWith)
		return m_hashWith;

	RLPStream s;
	streamRLP(s, _sig, m_chainId > 0 && _sig == WithoutSignature);
	h256 ret;
	/*auto ret = dev::sha3(s.out());
	if (_sig == WithSignature)
		m_hashWith = ret;
	 */
	return ret;
}



//TransactionBase::TransactionBase(bytesConstRef _rlpData, CheckTransaction _checkSig)
TransactionBase::TransactionBase(bytesConstRef _rlpData, int _checkSig)
{
    RLP const rlp(_rlpData);
    try
    {
        if (!rlp.isList())
            throw std::runtime_error("transaction RLP must be a list");

        m_nonce = rlp[0].toInt<u256>();
        m_gasPrice = rlp[1].toInt<u256>();
        m_gas = rlp[2].toInt<u256>();
        m_type = rlp[3].isEmpty() ? ContractCreation : MessageCall;
        m_receiveAddress = rlp[3].isEmpty() ? Address() : rlp[3].toHash<Address>(RLP::VeryStrict);
        m_value = rlp[4].toInt<u256>();

        if (!rlp[5].isData())
            throw std::runtime_error("transaction data RLP must be an array");

        m_data = rlp[5].toBytes();

        int const v = rlp[6].toInt<int>();
        h256 const r = rlp[7].toInt<u256>();
        h256 const s = rlp[8].toInt<u256>();

        if (isZeroSignature(r, s))
        {
            m_chainId = v;
            m_vrs = SignatureStruct{r, s, 0};
        }
        else
        {
            if (v > 36)
                m_chainId = (v - 35) / 2;
            else if (v == 27 || v == 28)
                m_chainId = -4;
            else
                throw std::runtime_error("error");

            m_vrs = SignatureStruct{r, s, static_cast<byte>(v - (m_chainId * 2 + 35))};

//            if (_checkSig >= CheckTransaction::Cheap && !m_vrs->isValid())
            if (_checkSig >= 1 && !m_vrs->isValid())
                throw std::runtime_error("error");
        }

//        if (_checkSig == CheckTransaction::Everything)
        if (_checkSig == 2)
            m_sender = sender();

        if (rlp.itemCount() > 9)
            throw std::runtime_error("error");
    }
    catch (Exception& _e)
    {
        throw std::runtime_error("error");
    }
}

#include <eth-crypto/core/sha3_wrap.h>

Address const& TransactionBase::sender() const
{
    if (!m_sender)
    {
        if (hasZeroSignature())
            m_sender = MaxAddress;
        else
        {
            if (!m_vrs)
                throw std::runtime_error("error");

            auto p = recover(*m_vrs, sha3(WithoutSignature));
            if (!p)
                throw std::runtime_error("error");

            std::vector<unsigned char> buf(p.data(), p.data()+ p.size);
            m_sender = right160(dev::ethash::sha3_ethash(buf));
        }
    }
    return m_sender;
}
