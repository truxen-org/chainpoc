package txnchain

import (
	"fmt"
	"math/big"

	"github.com/truxen-org/chainpoc/txnutil"
)
//Account information
type Address struct {
	Amount *big.Int
	Nonce  uint64
}

func NewAddress(amount *big.Int) *Address {
	return &Address{Amount: amount, Nonce: 0}
}

func NewAddressFromData(data []byte) *Address {
	address := &Address{}
	address.RlpDecode(data)
	return address
}

func (a *Address) AddFee(fee *big.Int) {
	a.Amount.Add(a.Amount, fee)
}

func (a *Address) RlpEncode() []byte {
	return txnutil.Encode([]interface{}{a.Amount, a.Nonce})
}

func (a *Address) RlpDecode(data []byte) {
	decoder := txnutil.NewValueFromBytes(data)

	a.Amount = decoder.Get(0).BigInt()
	a.Nonce = decoder.Get(1).Uint()
}

func (a *Address) String() string {
	return fmt.Sprintf("nonce = %v, amount = %v", a.Nonce, a.Amount)
}

type AddrStateStore struct {
	states map[string]*AddressState
}

func NewAddrStateStore() *AddrStateStore {
	return &AddrStateStore{states: make(map[string]*AddressState)}
}

func (s *AddrStateStore) Add(addr []byte, account *Address) *AddressState {
	state := &AddressState{addr: addr, Account: account}
	s.states[txnutil.Hex(addr)] = state
	return state
}

func (s *AddrStateStore) Get(addr []byte) *AddressState {
	return s.states[txnutil.Hex(addr)]
}

type AddressState struct {
	addr    []byte
	Account *Address
}

func NewAddressStateFromData(data []byte) *AddressState {
	as := &AddressState{}
	as.RlpDecode(data)
	return as
}

func (a *AddressState) RlpEncode() []byte {
	return txnutil.Encode([]interface{}{a.addr, a.Account.RlpEncode()})
}

func (a *AddressState) RlpDecode(data []byte) {
	decoder := txnutil.NewValueFromBytes(data)
	a.addr = decoder.Get(0).Bytes()
	a.Account = NewAddressFromData(decoder.Get(1).Bytes())
}

func (a *AddressState) String() string {
	return fmt.Sprintf("addr = %x,  %v \n", a.addr, a.Account)
}
