package txnchain

import (
	"fmt"
	"math/big"

	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
)

type BlockInfo struct {
	Number uint64
	Hash   []byte
	Parent []byte
}

func (bi *BlockInfo) RlpDecode(data []byte) {
	decoder := txnutil.NewValueFromBytes(data)

	bi.Number = decoder.Get(0).Uint()
	bi.Hash = decoder.Get(1).Bytes()
	bi.Parent = decoder.Get(2).Bytes()
}

func (bi *BlockInfo) RlpEncode() []byte {
	return txnutil.Encode([]interface{}{bi.Number, bi.Hash, bi.Parent})
}

type Header struct {
	Number         uint64
	Time           uint64
	PrevHash       []byte
	Coinbase       []byte
	Extra          []byte
	Nonce          []byte
	PubKey    []byte
	Signature      []byte
	Quoted         []byte
	Difficulty     uint64
	Signers        []byte
	TxSha          []byte
	ReceiptSha     []byte
	state          *txnutil.Trie
	contractStates map[string]*txnutil.Trie
}

func (header *Header) header() []interface{} {
	return []interface{}{
		header.Number,
		header.Time,
		header.PrevHash,
		header.Coinbase,
		header.Extra,
		header.Nonce,
		header.PubKey,
		header.Signature,
		header.Quoted,
		header.Difficulty,
		header.Signers,
		header.TxSha,
		header.ReceiptSha,
		header.state.Root,
	}
}
func (header *Header) Hash() (hsh []byte) {
	return txnutil.Sha3Bin(txnutil.NewValue(header.header()).Encode())
}

func (header *Header) String() string {
	r := `Number = %d
 Time = %d
 PrevHash = %x
 Coinbase = %x
 Root = %x
 Extra = %x
 Nonce = %x
 PubKey = 0x%x...([%d]byte)
 Signature = 0x%x...([%d]byte)
 Quoted = 0x%x...([%d]byte)
 Difficulty = %x
 Signers = %x
 TxSha = %x
 ReceiptSha = %x
`

	return fmt.Sprintf(r,
		header.Number,
		header.Time,
		header.PrevHash,
		header.Coinbase,
		header.state.Root,
		header.Extra,
		header.Nonce,
		header.PubKey[:3],
		len(header.PubKey),
		header.Signature[:3],
		len(header.Signature),
		header.Quoted[:3],
		len(header.Quoted),
		header.Difficulty,
		header.Signers,
		header.TxSha,
		header.ReceiptSha,
	)
}

type Block struct {
	header       *Header
	transactions []*Transaction
	Receipts     []*Receipt
}

func NewBlockFromBytes(raw []byte) *Block {
	block := &Block{}
	block.header = &Header{}
	block.RlpDecode(raw)

	return block
}

// New block takes a raw encoded string
func NewBlockFromRlpValue(rlpValue *txnutil.Value) *Block {
	block := &Block{}
	block.header = &Header{}
	block.RlpValueDecode(rlpValue)
	return block
}

func NewBlock(header *Header) *Block {
	block := &Block{
		header: header,
	}
	return block
}

func NewHeader(number uint64,
	root interface{},
	prevHash, base []byte) *Header {
	header := &Header{
		Number:         number,
		PrevHash:       prevHash,
		Coinbase:       base,
		contractStates: make(map[string]*txnutil.Trie),
	}
	header.state = txnutil.NewTrie(txndb.DB, root)
	return header
}

// Returns a hash of the block
func (block *Block) Hash() (hsh []byte) {
	// txnutil.Log.Debugf("geting block hash() - current state root = %x", block.header.state.Root)
	// defer func() {
	// 	txnutil.Log.Debugf("hash = %x", hsh)
	// }()

	return block.header.Hash()
}

func (block *Block) State() *txnutil.Trie {
	return block.header.state
}

func (block *Block) Transactions() []*Transaction {
	return block.transactions
}

func (block *Block) GetContract(addr []byte) *Contract {
	data := block.header.state.Get(string(addr))
	if data == "" {
		return nil
	}

	value := txnutil.NewValueFromBytes([]byte(data))
	if value.Len() == 2 {
		return nil
	}

	contract := &Contract{}
	contract.RlpDecode([]byte(data))

	cachedState := block.header.contractStates[string(addr)]
	if cachedState != nil {
		contract.state = cachedState
	} else {
		block.header.contractStates[string(addr)] = contract.state
	}

	return contract
}
func (block *Block) UpdateContract(addr []byte, contract *Contract) {
	// Make sure the state is synced
	//contract.State().Sync()

	block.header.state.Update(string(addr), string(contract.RlpEncode()))
}

func (block *Block) GetAddr(addr []byte) *Address {
	var address *Address

	data := block.State().Get(string(addr))
	if data == "" {
		address = NewAddress(big.NewInt(0))
	} else {
		address = NewAddressFromData([]byte(data))
	}

	return address
}

func (block *Block) UpdateAddr(addr []byte, address *Address) {
	// txnutil.Log.Debugf("UpdateAddr by block # %v : Address = %x, %v \n", block.header.Number, addr, address)
	block.header.state.Update(string(addr), string(address.RlpEncode()))
}

func (block *Block) PayFee(addr []byte, fee *big.Int) bool {
	contract := block.GetContract(addr)
	// If we can't pay the fee return
	if contract == nil || contract.Amount.Cmp(fee) < 0 /* amount < fee */ {
		fmt.Println("Contract has insufficient funds", contract.Amount, fee)

		return false
	}

	base := new(big.Int)
	contract.Amount = base.Sub(contract.Amount, fee)
	block.header.state.Update(string(addr), string(contract.RlpEncode()))

	data := block.header.state.Get(string(block.header.Coinbase))

	// Get the ether (Coinbase) and add the fee (gief fee to miner)
	ether := NewAddressFromData([]byte(data))

	base = new(big.Int)
	ether.Amount = base.Add(ether.Amount, fee)

	block.header.state.Update(string(block.header.Coinbase), string(ether.RlpEncode()))

	return true
}

func (block *Block) BlockInfo() BlockInfo {
	bi := BlockInfo{}
	data, _ := txndb.DB.Get(append(block.Hash(), []byte("Info")...))
	bi.RlpDecode(data)

	return bi
}

// Sync the block's state and contract respectively
func (block *Block) Sync() {
	// Sync all contracts currently in cache
	for _, val := range block.header.contractStates {
		val.Sync()
	}
	// Sync the block state itself
	block.header.state.Sync()
}

func (block *Block) Undo() {
	// Sync all contracts currently in cache
	for _, val := range block.header.contractStates {
		val.Undo()
	}
	// Sync the block state itself
	block.header.state.Undo()
}

func (block *Block) MakeContract(tx *Transaction) {
	contract := MakeContract(tx, NewState(block.header.state))
	if contract != nil {
		block.header.contractStates[string(tx.Hash()[12:])] = contract.state
	}
}

func (block *Block) rlpTxs() interface{} {
	// Marshal the transactions of this block
	encTx := make([]interface{}, len(block.transactions))
	for i, tx := range block.transactions {
		// Cast it to a string (safe)
		encTx[i] = tx.RlpData()
	}

	return encTx
}

func (block *Block) rlpReceipts() interface{} {
	// Marshal the receipts of this block
	receipts := make([]interface{}, len(block.Receipts))
	for i, receipt := range block.Receipts {
		// Cast it to a string (safe)
		receipts[i] = receipt.RlpData()
	}

	return receipts
}

func (block *Block) SetReceipts(receipts []*Receipt) {
	block.Receipts = receipts

	// Sha of the concatenated receipts
	block.header.ReceiptSha = txnutil.Sha3Bin(txnutil.Encode(block.rlpReceipts()))
}

func (block *Block) SetTransactions(txs []*Transaction) {
	block.transactions = txs

	for _, tx := range txs {
		block.MakeContract(tx)
	}
	block.header.TxSha = txnutil.Sha3Bin(txnutil.Encode(block.rlpTxs()))
}

func (block *Block) Value() *txnutil.Value {
	return txnutil.NewValue([]interface{}{block.rlpHeader(), block.rlpTxs(), block.rlpReceipts()})
}

func (block *Block) RlpEncode() []byte {
	// Encode a slice interface which contains the header and the list of
	// transactions.
	return block.Value().Encode()
}

func (block *Block) RlpDecode(data []byte) {
	rlpValue := txnutil.NewValueFromBytes(data)
	block.RlpValueDecode(rlpValue)
}

func (block *Block) RlpValueDecode(decoder *txnutil.Value) {
	header := decoder.Get(0)
	block.header.Number = header.Get(0).BigInt().Uint64()
	block.header.Time = header.Get(1).BigInt().Uint64()
	block.header.PrevHash = header.Get(2).Bytes()
	block.header.Coinbase = header.Get(3).Bytes()
	block.header.Extra = header.Get(4).Bytes()
	block.header.Nonce = header.Get(5).Bytes()
	block.header.PubKey = header.Get(6).Bytes()
	block.header.Signature = header.Get(7).Bytes()
	block.header.Quoted = header.Get(8).Bytes()
	block.header.Difficulty = header.Get(9).BigInt().Uint64()
	block.header.Signers = header.Get(10).Bytes()
	block.header.TxSha = header.Get(11).Bytes()
	block.header.ReceiptSha = header.Get(12).Bytes()
	block.header.state = txnutil.NewTrie(txndb.DB, header.Get(13).Val)
	block.header.contractStates = make(map[string]*txnutil.Trie)
	if decoder.Get(1).IsNil() == false { // Yes explicitness
		txes := decoder.Get(1)
		block.transactions = make([]*Transaction, txes.Len())
		for i := 0; i < txes.Len(); i++ {
			block.transactions[i] = NewTransactionFromValue(txes.Get(i))
		}
	}
	if decoder.Get(2).IsNil() == false { // Yes explicitness
		receipts := decoder.Get(2)
		block.Receipts = make([]*Receipt, receipts.Len())
		for i := 0; i < receipts.Len(); i++ {
			block.Receipts[i] = NewReceiptFromValue(receipts.Get(i))
		}
	}
}

func (block *Block) String() string {
	header := block.header
	v := fmt.Sprintf(`Hash = %x %v (Txs = %d)
 (Receipts = %d)
 `, block.Hash(), header, len(block.transactions), len(block.Receipts))

	if len(block.transactions) > 3 {
		for i, r := range block.transactions[:3] {
			v += fmt.Sprintf("transaction[%d]: %v \n", i, r)
		}
		v += "...\n"
		for i, r := range block.Receipts[:3] {
			v += fmt.Sprintf("receipt[%d]: %v \n", i, r)
		}
		v += "...\n"
	} else {
		for i, r := range block.transactions {
			v += fmt.Sprintf("transaction[%d]: %v \n", i, r)
		}
		for i, r := range block.Receipts {
			v += fmt.Sprintf("receipt[%d]: %v \n", i, r)
		}
	}
	return v
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header) *Block {
	cpy := *header

	return &Block{
		header:       &cpy,
		transactions: b.transactions,
		Receipts:     b.Receipts,
	}
}

func (block *Block) rlpHeader() *txnutil.Value {
	return txnutil.NewValue(block.header.header())
}

func (b *Block) Header() *Header { return CopyHeader(b.header) }

func CopyHeader(h *Header) *Header {
	cpy := *h

	// PrevHash       []byte
	// Coinbase       []byte
	// Extra          []byte
	// Nonce          []byte
	// PubKey         []byte
	// Signature      []byte
	// Quoted         []byte
	// TxSha          []byte
	// ReceiptSha     []byte
	// CopyProp(h.PubKey, cpy.PubKey)
	// CopyProp(h.PrevHash, cpy.PrevHash)
	// if len(h.Extra) > 0 {
	// 	cpy.Extra = make([]byte, len(h.Extra))
	// 	copy(cpy.Extra, h.Extra)
	// }
	return &cpy
}
func CopyProp(hs, cpys []byte) {
	l := len(hs)
	if l > 0 {
		cpys = make([]byte, l)
		copy(cpys, hs)
	}
}
