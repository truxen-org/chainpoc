package txnchain

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/truxen-org/chainpoc/crypto/secp256k1"
	"github.com/truxen-org/chainpoc/txnutil"
)

var ContractAddr = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type Transaction struct {
	Nonce     uint64
	Recipient []byte
	Value     *big.Int
	Data      []string
	Memory    []int
	v         byte
	r, s      []byte
}

func NewTransaction(to []byte, value *big.Int, data []string) *Transaction {
	tx := Transaction{Recipient: to, Value: value}
	tx.Nonce = 0

	// Serialize the data
	tx.Data = data

	return &tx
}

// XXX Deprecated
func NewTransactionFromData(data []byte) *Transaction {
	return NewTransactionFromBytes(data)
}

func NewTransactionFromBytes(data []byte) *Transaction {
	tx := &Transaction{}
	tx.RlpDecode(data)

	return tx
}

func NewTransactionFromValue(val *txnutil.Value) *Transaction {
	tx := &Transaction{}
	tx.RlpValueDecode(val)

	return tx
}

func (tx *Transaction) Hash() []byte {
	data := make([]interface{}, len(tx.Data))
	for i, val := range tx.Data {
		data[i] = val
	}

	preEnc := []interface{}{
		tx.Nonce,
		tx.Recipient,
		tx.Value,
		data,
	}

	return txnutil.Sha3Bin(txnutil.Encode(preEnc))
}

func (tx *Transaction) IsContract() bool {
	return bytes.Compare(tx.Recipient, ContractAddr) == 0
}

func (tx *Transaction) Signature(key []byte) []byte {
	hash := tx.Hash()

	sig, _ := secp256k1.Sign(hash, key)

	return sig
}

func (tx *Transaction) PublicKey() []byte {
	hash := tx.Hash()

	// If we don't make a copy we will overwrite the existing underlying array
	dst := make([]byte, len(tx.r))
	copy(dst, tx.r)

	sig := append(dst, tx.s...)
	sig = append(sig, tx.v-27)

	pubkey, _ := secp256k1.RecoverPubkey(hash, sig)

	return pubkey
}

//get address from pubkey
func (tx *Transaction) Sender() []byte {
	pubkey := tx.PublicKey()

	// Validate the returned key.
	// Return nil if public key isn't in full format
	if pubkey[0] != 4 {
		return nil
	}

	return txnutil.Sha3Bin(pubkey[1:])[12:]
}

func (tx *Transaction) Sign(privk []byte) error {

	sig := tx.Signature(privk)

	tx.r = sig[:32]
	tx.s = sig[32:64]
	tx.v = sig[64] + 27

	return nil
}

func (tx *Transaction) RlpData() interface{} {
	// Prepare the transaction for serialization
	return []interface{}{
		tx.Nonce,
		tx.Recipient,
		tx.Value,
		txnutil.NewSliceValue(tx.Data).Slice(),
		tx.v,
		tx.r,
		tx.s,
	}
}
func (tx *Transaction) String() string {

	return fmt.Sprintf(`Nonce:	%d
	Recipient: 0x%x
	Value: %v
	data: %v
	v:	%x
	r: 0x%x
	s: 0x%x`,
		tx.Nonce,
		tx.Recipient,
		tx.Value,
		tx.Data,
		tx.v,
		tx.r,
		tx.s)
}

func (tx *Transaction) RlpValue() *txnutil.Value {
	return txnutil.NewValue(tx.RlpData())
}

func (tx *Transaction) RlpEncode() []byte {
	return tx.RlpValue().Encode()
}

func (tx *Transaction) RlpDecode(data []byte) {
	tx.RlpValueDecode(txnutil.NewValueFromBytes(data))
}

func (tx *Transaction) RlpValueDecode(decoder *txnutil.Value) {
	tx.Nonce = decoder.Get(0).Uint()
	tx.Recipient = decoder.Get(1).Bytes()
	tx.Value = decoder.Get(2).BigInt()

	d := decoder.Get(3)
	tx.Data = make([]string, d.Len())
	for i := 0; i < d.Len(); i++ {
		tx.Data[i] = d.Get(i).Str()
	}

	// TODO something going wrong here
	tx.v = byte(decoder.Get(4).Uint())
	tx.r = decoder.Get(5).Bytes()
	tx.s = decoder.Get(6).Bytes()
}

type Receipts []*Receipt

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	ReceiptStatusSuccessful = uint64(1)
)

type AccountUpdate struct {
	address, data []byte
}

func (au *AccountUpdate) RlpValue() interface{} {
	return []interface{}{au.address, au.data}
}

type Receipt struct {
	TxHash        []byte
	PostState     []byte
	Status        uint64
	AddressStates []*AddressState
}

func NewReceipt(tx []byte, root []byte, failed bool) *Receipt {
	r := &Receipt{
		TxHash:    tx,
		PostState: root,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

func NewReceiptFromValue(val *txnutil.Value) *Receipt {
	r := &Receipt{}
	r.RlpValueDecode(val)

	return r
}

func (self *Receipt) SetAddressStates(ass *AddrStateStore) {
	states := make([]*AddressState, len(ass.states))
	i := 0
	for _, v := range ass.states {
		states[i] = v
		i++
	}
	self.AddressStates = states
}

func (self *Receipt) RlpValueDecode(decoder *txnutil.Value) {
	self.TxHash = decoder.Get(0).Bytes()
	self.PostState = decoder.Get(1).Bytes()
	self.Status = decoder.Get(2).Uint()
	if decoder.Get(3).IsNil() == false {
		ass := decoder.Get(3)
		self.AddressStates = make([]*AddressState, ass.Len())
		for i := 0; i < ass.Len(); i++ {
			as := NewAddressStateFromData(ass.Get(i).Bytes())
			self.AddressStates[i] = as
		}
	}
}

func (self *Receipt) RlpData() interface{} {
	return []interface{}{self.TxHash, self.PostState, self.Status, self.RlpAddressStates()}
}

func (self *Receipt) RlpAddressStates() interface{} {
	rlps := make([]interface{}, len(self.AddressStates))
	for i, as := range self.AddressStates {
		rlps[i] = as.RlpEncode()
	}
	return rlps
}

func (self *Receipt) Hash() []byte {
	data := self.RlpData()
	return txnutil.Sha3Bin(txnutil.NewValue(data).Encode())
}

func (self *Receipt) String() string {
	base := fmt.Sprintf(` 
	TxHash:	0x%x
	PostState: 0x%x
	Status: %v
	AddressStates: %d`,
		self.TxHash,
		self.PostState,
		self.Status,
		len(self.AddressStates))
	for i, as := range self.AddressStates {
		base += fmt.Sprintf(strings.Repeat("\t", i+1)+"state[%d]: %v ", i, as)
	}
	return base
}
