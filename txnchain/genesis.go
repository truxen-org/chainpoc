package txnchain

import (
	"math/big"

	"github.com/truxen-org/chainpoc/txnutil"
)

/*
 * This is the special genesis block.
 */

var ZeroHash256 = make([]byte, 32)
var ZeroHash160 = make([]byte, 20)
var EmptyShaList = txnutil.Sha3Bin(txnutil.Encode([]interface{}{}))

func NewGenesis() []interface{} {
	signersArray := txnutil.Config.Signers
	signersBytes := make([]byte, 0, SignerBytesLen*len(signersArray))
	for _, s := range signersArray {
		signersBytes = append(signersBytes, txnutil.FromHex(s)...)
	}
	var GenesisHeader = []interface{}{
		//Number
		uint64(0),
		// Time
		uint64(0),
		//previous hash
		ZeroHash256,
		// Coinbase
		ZeroHash160,
		// Extra
		"",
		// Nonce
		txnutil.Sha3Bin(big.NewInt(42).Bytes()),
		"",
		"",
		"",
		//Difficulty
		uint64(0),
		//Signers
		signersBytes,
		// Sha of transactions EmptyShaList,
		txnutil.Sha3Bin(txnutil.Encode([]interface{}{})),
		// Sha of receives
		txnutil.Sha3Bin(txnutil.Encode([]interface{}{})),
		// Root state
		"",
	}

	var Genesis = []interface{}{GenesisHeader, []interface{}{}, []interface{}{}}
	return Genesis
}
