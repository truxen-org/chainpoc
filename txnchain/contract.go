package txnchain

import (
	"math/big"

	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
)

type Contract struct {
	Amount *big.Int
	Nonce  uint64
	state  *txnutil.Trie
}

func NewContract(Amount *big.Int, root []byte) *Contract {
	contract := &Contract{Amount: Amount, Nonce: 0}
	contract.state = txnutil.NewTrie(txndb.DB, string(root))

	return contract
}

func (c *Contract) RlpEncode() []byte {
	return txnutil.Encode([]interface{}{c.Amount, c.Nonce, c.state.Root})
}

func (c *Contract) RlpDecode(data []byte) {
	decoder := txnutil.NewValueFromBytes(data)

	c.Amount = decoder.Get(0).BigInt()
	c.Nonce = decoder.Get(1).Uint()
	c.state = txnutil.NewTrie(txndb.DB, decoder.Get(2).Interface())
}

func (c *Contract) Addr(addr []byte) *txnutil.Value {
	return txnutil.NewValueFromBytes([]byte(c.state.Get(string(addr))))
}

func (c *Contract) SetAddr(addr []byte, value interface{}) {
	c.state.Update(string(addr), string(txnutil.NewValue(value).Encode()))
}

func (c *Contract) State() *txnutil.Trie {
	return c.state
}

func (c *Contract) GetMem(num int) *txnutil.Value {
	nb := txnutil.BigToBytes(big.NewInt(int64(num)), 256)

	return c.Addr(nb)
}

func MakeContract(tx *Transaction, state *State) *Contract {
	// Create contract if there's no recipient
	if tx.IsContract() {
		addr := tx.Hash()[12:]

		value := tx.Value
		contract := NewContract(value, []byte(""))
		state.trie.Update(string(addr), string(contract.RlpEncode()))
		for i, val := range tx.Data {
			if len(val) > 0 {
				bytNum := txnutil.BigToBytes(big.NewInt(int64(i)), 256)
				contract.state.Update(string(bytNum), string(txnutil.Encode(val)))
			}
		}
		state.trie.Update(string(addr), string(contract.RlpEncode()))

		return contract
	}

	return nil
}
