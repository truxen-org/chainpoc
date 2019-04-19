package txnchain

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/big"

	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
)

type BlockChain struct {
	// The famous, the fabulous Mister GENESIIIIIIS (block)
	genesisBlock *Block
	// Last known total difficulty
	TD *big.Int

	LastBlockNumber uint64

	CurrentBlock  *Block
	LastBlockHash []byte
}

func NewBlockChain() *BlockChain {
	bc := &BlockChain{}
	genesis := NewGenesis()
	bc.genesisBlock = NewBlockFromBytes(txnutil.Encode(genesis))

	bc.setLastBlock()

	return bc
}

func (bc *BlockChain) CreateHeader(coinbase []byte) *Header {
	var root interface{}
	var number uint64
	hash := ZeroHash256

	if bc.CurrentBlock != nil {
		number = bc.CurrentBlock.Header().Number + 1
		root = bc.CurrentBlock.State().Root
		hash = bc.CurrentBlock.Hash()
	}
	header := NewHeader(
		number,
		root,
		hash,
		coinbase,
	)

	return header
}

func (bc *BlockChain) HasBlock(hash []byte) bool {
	data, _ := txndb.DB.Get(hash)
	return len(data) != 0
}

func (bc *BlockChain) GenesisBlock() *Block {
	return bc.genesisBlock
}

func (bc *BlockChain) GetBlockByNumber(number uint64) *Block {
	last := bc.CurrentBlock.Header()
	if number == last.Number {
		return bc.CurrentBlock
	}
	for i := last.Number; i >= 0; i-- {
		hash := last.PrevHash
		if i == number+1 {
			return bc.GetBlock(hash)
		}
	}
	return nil
}

// Get chain return blocks from hash up to max in RLP format
func (bc *BlockChain) GetChainFromHash(hash []byte, max uint64) []interface{} {
	var chain []interface{}
	// Get the current hash to start with
	currentHash := bc.CurrentBlock.Hash()
	// Get the last number on the block chain
	lastNumber := bc.BlockInfo(bc.CurrentBlock).Number
	// Get the parents number
	parentNumber := bc.BlockInfoByHash(hash).Number
	// Get the min amount. We might not have max amount of blocks
	count := uint64(math.Min(float64(lastNumber-parentNumber), float64(max)))
	startNumber := parentNumber + count

	num := lastNumber
	for ; num > startNumber; currentHash = bc.GetBlock(currentHash).header.PrevHash {
		num--
	}
	for i := uint64(0); bytes.Compare(currentHash, hash) != 0 && num >= parentNumber && i < count; i++ {
		// Get the block of the chain
		block := bc.GetBlock(currentHash)
		if block == nil {
			log.Fatalf("block not found: %x #%d ", currentHash, num)
		}
		currentHash = block.header.PrevHash

		chain = append(chain, block.Value().Val)

		num--
	}

	return chain
}

//get amount number blocks from block with hash
func (bc *BlockChain) GetChain(hash []byte, amount int) []*Block {
	genHash := bc.genesisBlock.Hash()

	block := bc.GetBlock(hash)
	var blocks []*Block

	for i := 0; i < amount && block != nil; block = bc.GetBlock(block.header.PrevHash) {
		blocks = append([]*Block{block}, blocks...)

		if bytes.Compare(genHash, block.Hash()) == 0 {
			break
		}
		i++
	}

	return blocks
}

func (bc *BlockChain) GetHeader(hash []byte) *Header {
	block := bc.GetBlock(hash)
	if block == nil {
		// genHash := bc.genesisBlock.Hash()
		// if bytes.Compare(genHash, hash) == 0 {
		// 	return bc.genesisBlock.Header()
		// }
		log.Fatalf("cannot find block: %x", hash)
	}
	return block.header
}

func (bc *BlockChain) setLastBlock() {
	data, _ := txndb.DB.Get([]byte("LastBlock"))
	if len(data) != 0 {
		block := NewBlockFromBytes(data)
		info := bc.BlockInfo(block)
		bc.CurrentBlock = block
		bc.LastBlockHash = block.Hash()
		bc.LastBlockNumber = info.Number

		log.Printf("[CHAIN] Last known block height #%d\n", bc.LastBlockNumber)
	}

}

// Add a block to the chain and record addition information
func (bc *BlockChain) Add(block *Block) {
	bc.writeBlockInfo(block)
	// Prepare the genesis block
	bc.CurrentBlock = block
	bc.LastBlockHash = block.Hash()
	encodedBlock := block.RlpEncode()
	txndb.DB.Put(bc.LastBlockHash, encodedBlock)
	txndb.DB.Put([]byte("LastBlock"), encodedBlock)
	// log.Printf("[CHAIN] Added block #%d (%x...) Root(%x...)\n", block.header.Number, block.Hash()[:3], block.State().Root)
	log.Printf("[CHAIN] Added block #%d (%x...) Df=%d\n", block.header.Number, block.Hash()[:3], block.header.Difficulty)
}

func (bc *BlockChain) RollbackTo(block *Block) {
	bc.CurrentBlock = block
	bc.LastBlockHash = block.Hash()
	encodedBlock, _ := txndb.DB.Get(bc.LastBlockHash)
	txndb.DB.Put([]byte("LastBlock"), encodedBlock)
	txnutil.Log.Debugf("[CHAIN] RollbackTo #%d (%x...) Root(%x...)\n", block.header.Number, block.Hash()[:3], block.State().Root)
}

func (bc *BlockChain) GetBlock(hash []byte) *Block {
	// log.Printf("Get: %x", hash)
	data, _ := txndb.DB.Get(hash)
	if len(data) == 0 {
		log.Printf("cannot get block. hash = %x", hash)
		return nil
	}
	return NewBlockFromBytes(data)
}

func (bc *BlockChain) GetTotalDifficulty(hash []byte) uint64 {
	td := uint64(0)
	block := bc.GetBlock(hash)
	txnutil.Log.Debugf("counting td start from #%d: %x", block.header.Number, hash)
	startNumber := block.header.Number
	for i := startNumber; i > 0; i-- {
		td += block.header.Difficulty
		hs := block.header.PrevHash
		// log.Printf(" #%d: %x... diff=%d", block.header.Number, block.Hash()[:3], block.header.Difficulty)
		block = bc.GetBlock(hs)
	}
	txnutil.Log.Debugf("total diff = %d ", td)
	return td
}

func (bc *BlockChain) PrintLocalChain() {
	block := bc.CurrentBlock
	startNumber := bc.LastBlockNumber
	for i := startNumber; i > 0; i-- {
		signer := SignerFromPubKey(block.header.PubKey)
		fmt.Printf("\t#%d\t%x...\t%d\tsigned by %s...\n", block.header.Number, block.Hash()[:1], block.header.Difficulty, signer[0:2])
		hs := block.header.PrevHash
		block = bc.GetBlock(hs)
	}
}

func (bc *BlockChain) BlockInfoByHash(hash []byte) BlockInfo {
	bi := BlockInfo{}
	data, _ := txndb.DB.Get(append(hash, []byte("Info")...))
	bi.RlpDecode(data)

	return bi
}

func (bc *BlockChain) BlockInfo(block *Block) BlockInfo {
	bi := BlockInfo{}
	data, _ := txndb.DB.Get(append(block.Hash(), []byte("Info")...))
	bi.RlpDecode(data)

	return bi
}

// Unexported method for writing extra non-essential block info to the db
func (bc *BlockChain) writeBlockInfo(block *Block) {
	bc.LastBlockNumber = block.Header().Number
	bi := BlockInfo{Number: bc.LastBlockNumber, Hash: block.Hash(), Parent: block.header.PrevHash}

	// For now we use the block hash with the words "info" appended as key
	txndb.DB.Put(append(block.Hash(), []byte("Info")...), bi.RlpEncode())
}

func (bc *BlockChain) Stop() {
	if bc.CurrentBlock != nil {
		log.Println("[CHAIN] Stopped")
	}
}

func (bc *BlockChain) Reorg(newBlock *Block) error {
	var (
		newChain, oldChain []*Block
		commonBlock        *Block
	)
	oldBlock := bc.CurrentBlock
	// log.Printf("oldBlockNumber=%d", oldBlock.header.Number)
	if oldBlock.header.Number > newBlock.header.Number {
		for ; oldBlock != nil && oldBlock.header.Number != newBlock.header.Number; oldBlock = bc.GetBlock(oldBlock.header.PrevHash) {
			oldChain = append(oldChain, oldBlock)
		}
	} else {
		for ; newBlock != nil && newBlock.header.Number != oldBlock.header.Number; newBlock = bc.GetBlock(newBlock.header.PrevHash) {
			newChain = append(newChain, newBlock)
		}
	}

	if oldBlock == nil {
		return fmt.Errorf("Invalid old chain")
	}
	if newBlock == nil {
		return fmt.Errorf("Invalid new chain")
	}

	for {
		if bytes.Equal(oldBlock.Hash(), newBlock.Hash()) {
			commonBlock = oldBlock
			break
		}
		oldChain = append(oldChain, oldBlock)
		newChain = append(newChain, newBlock)
		oldBlock, newBlock = bc.GetBlock(oldBlock.header.PrevHash), bc.GetBlock(newBlock.header.PrevHash)
		if oldBlock == nil {
			return fmt.Errorf("Invalid old chain")
		}
		if newBlock == nil {
			return fmt.Errorf("Invalid new chain")
		}
	}
	if len(oldChain) > 0 && len(newChain) > 0 {
		log.Printf("[CHAIN] Chain splited from %d hash=%x... drop %d from %x; add %d from %x", commonBlock.header.Number, commonBlock.Hash()[:3],
			len(oldChain), oldChain[0].Hash()[:3], len(newChain), newChain[0].Hash()[:3])
	} else {
		log.Printf("ERROR: Impossible reorg, please file an issue. oldnum=%d oldhash=%x newnum=%d newhash=%x", oldBlock.header.Number, oldBlock.Hash(), newBlock.header.Number, newBlock.Hash())
	}
	bc.RollbackTo(commonBlock)
	for i := len(newChain) - 1; i >= 0; i-- {
		log.Printf("reorg: adding new block #%d %x...", newChain[i].header.Number, newChain[i].Hash()[:3])
		bc.SyncToCurrent(newChain[i])
		bc.Add(newChain[i])
	}
	return nil
}

func (bc *BlockChain) ApplyAddressStates(processor *Block, receipts []*Receipt) error {
	for _, rc := range receipts {
		for _, as := range rc.AddressStates {
			processor.UpdateAddr(as.addr, as.Account)
		}
	}
	return nil
}
func (bc *BlockChain) AccumelateRewards(processor *Block, block *Block) error {
	// processor := bm.bc.CurrentBlock
	// processor := block
	// Get the coinbase rlp data
	addr := processor.GetAddr(block.header.Coinbase)
	// Reward amount of ether to the coinbase address
	addr.AddFee(BlockReward)

	processor.UpdateAddr(block.header.Coinbase, addr)
	return nil
}

//sync state for blocks
func (bc *BlockChain) SyncToCurrent(block *Block) error {

	//PoI: instead of process txs, update address states only.
	if err := bc.ApplyAddressStates(bc.CurrentBlock, block.Receipts); err != nil {
		return err
	}
	// txnutil.Log.Debugf("CurrentBlock.Root before AccumelateRewards: %x \n", bc.CurrentBlock.State().Root)
	if err := bc.AccumelateRewards(bc.CurrentBlock, block); err != nil {
		return err
	}
	// txnutil.Log.Debugf("CurrentBlock.Root After AccumelateRewards: %x \n", bc.CurrentBlock.State().Root)

	//PoI: ApplyAddressStates makes state test pass same as apply txs.
	if !block.State().Cmp(bc.CurrentBlock.State()) {
		return fmt.Errorf("Invalid merkle root. Expected %x, got %x", block.State().Root, bc.CurrentBlock.State().Root)
	}
	// Sync the current block's state to the database and cancelling out the deferred Undo
	bc.CurrentBlock.Sync()
	return nil
}
