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

#pragma once

#include <eth-crypto/core/Common.h>
#include <eth-crypto/crypto/Common.h>
#include <eth-crypto/core//RLP.h>
//#include <eth-crypto/core/SHA3.h>

#include <boost/optional.hpp>

namespace dev
{
namespace eth
{

struct EVMSchedule;

/// Named-boolean type to encode whether a signature be included in the serialisation process.
enum IncludeSignature
{
	WithoutSignature = 0,	///< Do not include a signature.
	WithSignature = 1,		///< Do include a signature.
};

/*enum class CheckTransaction
{
	None,
	Cheap,
	Everything
};
*/
/// Encodes a transaction, ready to be exported to or freshly imported from RLP.
class TransactionBase
{
public:
	/// Constructs a null transaction.
	TransactionBase() {}


	/// Constructs a signed message-call transaction.
	TransactionBase(u256 const& _value, u256 const& _gasPrice, u256 const& _gas, Address const& _dest, bytes const& _data, u256 const& _nonce, Secret const& _secret, int _chain_id): m_type(MessageCall), m_nonce(_nonce), m_value(_value), m_receiveAddress(_dest), m_gasPrice(_gasPrice), m_gas(_gas), m_data(_data), m_chainId(_chain_id) { sign(_secret); }



	/// Serialises this transaction to an RLPStream.
	/// @throws TransactionIsUnsigned if including signature was requested but it was not initialized
	void streamRLP(RLPStream& _s, IncludeSignature _sig = WithSignature, bool _forEip155hash = false) const;

	/// @returns the RLP serialisation of this transaction.
	bytes rlp(IncludeSignature _sig = WithSignature) const { RLPStream s; streamRLP(s, _sig); return s.out(); }

	/// @returns the SHA3 hash of the RLP serialisation of this transaction.
	h256 sha3(IncludeSignature _sig = WithSignature) const;

	/// @returns the amount of ETH to be transferred by this (message-call) transaction, in Wei. Synonym for endowment().
	u256 value() const { return m_value; }

	/// @returns the base fee and thus the implied exchange rate of ETH to GAS.
	u256 gasPrice() const { return m_gasPrice; }

	/// @returns the total gas to convert, paid for from sender's account. Any unused gas gets refunded once the contract is ended.
	u256 gas() const { return m_gas; }

	/// @returns the receiving address of the message-call transaction (undefined for contract-creation transactions).
	Address receiveAddress() const { return m_receiveAddress; }

	/// Synonym for receiveAddress().
	Address to() const { return m_receiveAddress; }



	/// @returns the data associated with this (message-call) transaction. Synonym for initCode().
	bytes const& data() const { return m_data; }

	/// @returns the transaction-count of the sender.
	u256 nonce() const { return m_nonce; }

	/// Sets the nonce to the given value. Clears any signature.
	void setNonce(u256 const& _n) { clearSignature(); m_nonce = _n; }

	/// @returns true if the transaction was signed
	bool hasSignature() const { return m_vrs.is_initialized(); }

	/// @returns true if the transaction was signed with zero signature
	bool hasZeroSignature() const { return m_vrs && isZeroSignature(m_vrs->r, m_vrs->s); }

	/// @returns true if the transaction uses EIP155 replay protection
	bool isReplayProtected() const { return m_chainId != -4; }

	/// @returns the signature of the transaction (the signature has the sender encoded in it)
	/// @throws TransactionIsUnsigned if signature was not initialized


	void sign(Secret const& _priv);			///< Sign the transaction.


protected:
	/// Type of transaction.
	enum Type
	{
		NullTransaction,				///< Null transaction.
		ContractCreation,				///< Transaction to create contracts - receiveAddress() is ignored.
		MessageCall						///< Transaction to invoke a message call - receiveAddress() is used.
	};

	static bool isZeroSignature(u256 const& _r, u256 const& _s) { return !_r && !_s; }

	/// Clears the signature.
	void clearSignature() { m_vrs = SignatureStruct(); }

	Type m_type = NullTransaction;		///< Is this a contract-creation transaction or a message-call transaction?
	u256 m_nonce;						///< The transaction-count of the sender.
	u256 m_value;						///< The amount of ETH to be transferred by this transaction. Called 'endowment' for contract-creation transactions.
	Address m_receiveAddress;			///< The receiving address of the transaction.
	u256 m_gasPrice;					///< The base fee and thus the implied exchange rate of ETH to GAS.
	u256 m_gas;							///< The total gas to convert, paid for from sender's account. Any unused gas gets refunded once the contract is ended.
	bytes m_data;						///< The data associated with the transaction, or the initialiser if it's a creation transaction.
	boost::optional<SignatureStruct> m_vrs;	///< The signature of the transaction. Encodes the sender.
	int m_chainId = -4;					///< EIP155 value for calculating transaction hash https://github.com/ethereum/EIPs/issues/155

	mutable h256 m_hashWith;			///< Cached hash of transaction with signature.
	mutable Address m_sender;			///< Cached sender, determined from signature.
};

/// Nice name for vector of Transaction.
using TransactionBases = std::vector<TransactionBase>;

/*/// Simple human-readable stream-shift operator.
inline std::ostream& operator<<(std::ostream& _out, TransactionBase const& _t)
{
	_out << _t.sha3().abridged() << "{";
	if (_t.receiveAddress())
		_out << _t.receiveAddress().abridged();
	else
		_out << "[CREATE]";

	_out << "/" << _t.data().size() << "$" << _t.value() << "+" << _t.gas() << "@" << _t.gasPrice();
	_out << "<-" << _t.safeSender().abridged() << " #" << _t.nonce() << "}";
	return _out;
}
*/
}
}
