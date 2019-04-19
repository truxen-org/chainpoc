package txnchain

import (
	"bytes"
	"encoding/hex"
	"log"
	"math/big"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/truxen-org/chainpoc/txnwire"

	"github.com/truxen-org/chainpoc/txnutil"
)

// TODO rename to state manager
type BlockManager struct {
	// Mutex for locking the block processor. Blocks can only be handled one at a time
	mutex sync.Mutex

	// The block chain :)
	bc *BlockChain 

	// States for addresses. You can watch any address
	// at any given time
	addrStateStore *AddrStateStore

	// Stack for processing contracts
	stack *Stack
	// non-persistent key/value memory storage
	mem map[string]*big.Int

	TransactionPool *TxPool

	Speaker PublicSpeaker

	Cnsnss Consensus
}

func AddTestNetFunds(block *Block) {
	for _, addr := range []string{
		"8a40bfaa73256b60764c1bf40675a99083efb075", 
		"e6716f9544a56c530d868e4bfbacb172315bdead", 
		"1e12515ce3e0f817a4ddef9ca55788a1d66bd2df", 
		"1a26338f0d905e295fccb71fa9ea849ffa12aaf4", 
	} {
		//log.Println("2^200 Wei to", addr)
		codedAddr, _ := hex.DecodeString(addr)
		addr := block.GetAddr(codedAddr)
		addr.Amount = txnutil.Big("100000")
		block.UpdateAddr(codedAddr, addr)
	}
}

func NewBlockManager(speaker PublicSpeaker, cns Consensus) *BlockManager {
	bm := &BlockManager{
		//server: s,
		bc:             NewBlockChain(),
		stack:          NewStack(),
		mem:            make(map[string]*big.Int),
		Speaker:        speaker,
		addrStateStore: NewAddrStateStore(),
		Cnsnss:         cns,
	}

	if bm.bc.CurrentBlock == nil {
		AddTestNetFunds(bm.bc.genesisBlock)

		bm.bc.genesisBlock.State().Sync()
		// Prepare the genesis block
		bm.bc.Add(bm.bc.genesisBlock)

		//log.Printf("root %x\n", bm.bc.genesisBlock.State().Root)
		//bm.bc.genesisBlock.PrintHash()
	}

	log.Printf("Last local block:  #%d  %x\n", bm.bc.CurrentBlock.Header().Number, bm.bc.CurrentBlock.Hash())

	return bm
}

// Watches any given address and puts it in the address state store
func (bm *BlockManager) WatchAddr(addr []byte) *AddressState {
	account := bm.bc.CurrentBlock.GetAddr(addr)

	return bm.addrStateStore.Add(addr, account)
}

func (bm *BlockManager) GetAddrState(addr []byte) *AddressState {
	account := bm.addrStateStore.Get(addr)
	if account == nil {
		a := bm.bc.CurrentBlock.GetAddr(addr)
		account = &AddressState{addr: addr, Account: a}
	}

	return account
}

func (bm *BlockManager) BlockChain() *BlockChain {
	return bm.bc
}

//Execute transaction while mining
func (bm *BlockManager) ApplyTransactions(block *Block, txs []*Transaction) ([]*Receipt, error) {
	// block := bm.bc.CurrentBlock
	// Process each transaction/contract
	if txnutil.Config.Profile {
		f, _ := os.Create("cpuprofile")
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	receipts := make([]*Receipt, len(txs))
	for i, tx := range txs {
		// 	// If there's no recipient, it's a contract deployment
		// 	if tx.IsContract() {
		// 		block.MakeContract(tx)
		// 	} else {
		// 		if contract := block.GetContract(tx.Recipient); contract != nil {

		// 			//TODO: get recepits
		// 			bm.ProcessContract(contract, tx, block)
		// 		} else {
		// start := time.Now()
		hash := txnutil.Hex(tx.Hash())
		sender := bm.TransactionPool.getSender(hash)
		if len(sender) == 0 {
			sender = tx.Sender()
		}
		receipts[i], _ = bm.TransactionPool.ProcessTransaction(sender, tx, block)
		delete(bm.TransactionPool.senders, hash)
		// fmt.Println("++++++++++++++++++++++ ProcessTransaction ", time.Since(start))
		// 	}
		// }
	}
	// block.State().Cache().Clear()

	// memf, err := os.Create("mem_profile")
	// if err != nil {
	// 	log.Fatal("could not create memory profile: ", err)
	// }
	// if err := pprof.WriteHeapProfile(memf); err != nil {
	// 	log.Fatal("could not write memory profile: ", err)
	// }
	// memf.Close()
	return receipts, nil
}

// Block processing and validating with a given (temporarily) state
func (bm *BlockManager) ProcessBlock(block *Block) error {
	// Processing a blocks may never happen simultaneously
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	// Defer the Undo on the Trie. If the block processing happened
	// we don't want to undo but since undo only happens on dirty
	// nodes this won't happen because Commit would have been called
	// before that.
	defer bm.bc.CurrentBlock.Undo()

	hash := block.Hash()

	if bm.bc.HasBlock(hash) {
		return nil
	}

	// Check if we have the parent hash, if it isn't known we discard it
	// Reasons might be catching up or simply an invalid block
	// or future block
	if !bm.bc.HasBlock(block.header.PrevHash) {
		return ParentError(block.header.PrevHash)
	}
	// log.Printf("block to verify: %v \n", block)
	// Process the transactions on to current block
	// bm.ApplyTransactions(bm.bc.CurrentBlock, block.Transactions())

	// Block validation
	if err := bm.ValidateBlock(block); err != nil {
		return err
	}
	if bytes.Equal(block.header.PrevHash, bm.bc.LastBlockHash) {
		if err := bm.bc.SyncToCurrent(block); err != nil {
			return err
		}
		// Add the block to the chain
		bm.bc.Add(block)
	} else {
		//new block must point to a previous block in local chain
		externTD := bm.bc.GetTotalDifficulty(block.header.PrevHash) + block.header.Difficulty
		localTD := bm.bc.GetTotalDifficulty(bm.bc.LastBlockHash)
		log.Printf("externTD=%d; localTD=%d", externTD, localTD)
		// if externTD == localTD && block.header.Number == bm.bc.LastBlockNumber {
		// 	return nil
		// }
		reorg := externTD > localTD || (externTD == localTD && block.header.Number <= bm.bc.LastBlockNumber)
		if !reorg {
			return nil
		}
		if err := bm.bc.Reorg(block); err != nil {
			return err
		}
	}
	// Broadcast the valid block back to the wire
	bm.Speaker.Broadcast(txnwire.MsgBlockTy, []interface{}{block.Value().Val})

	return nil
}

// Validates the current block. Returns an error if the block was invalid,
// an receive or anything that isn't on the current block chain.
// Validation validates easy over difficult (dagger takes longer time = difficult)
func (bm *BlockManager) ValidateBlock(block *Block) error {

	diff := block.header.Time - bm.bc.CurrentBlock.header.Time
	if diff < 0 {
		return ValidationError("Block timestamp less then prev block %v", diff)
	}

	// New blocks must be within the 15 minute range of the last block.
	// if diff > uint64(15*time.Minute) {
	// 	return ValidationError("Block is too far in the future of last block (> 15 minutes)")
	// }
	recSha := txnutil.Sha3Bin(txnutil.Encode(block.rlpReceipts()))
	if !bytes.Equal(recSha, block.header.ReceiptSha) {
		return ValidationError("ReceiptSha is not correct!")
	}
	if err := bm.Cnsnss.VerifyHeader(block.header); err != nil {
		return ValidationError("VerifyHeader (%v)", err)
	}

	return nil
}

func (bm *BlockManager) Stop() {
	bm.bc.Stop()
}

func (bm *BlockManager) ProcessContract(contract *Contract, tx *Transaction, block *Block) {
	// Recovering function in case the VM had any errors
	/*
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Recovered from VM execution with err =", r)
			}
		}()
	*/

	vm := &Vm{}
	vm.Process(contract, NewState(block.header.state), RuntimeVars{
		address:     tx.Hash()[12:],
		blockNumber: block.BlockInfo().Number,
		sender:      tx.Sender(),
		prevHash:    block.header.PrevHash,
		coinbase:    block.header.Coinbase,
		time:        int64(block.header.Time),
		txValue:     tx.Value,
		txData:      tx.Data,
	})
}

func (bm *BlockManager) AfterMined(block *Block) error {

	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	// bm.bc.CurrentBlock.Sync()
	block.Sync()
	// Broadcast the valid block back to the wire
	bm.Speaker.Broadcast(txnwire.MsgBlockTy, []interface{}{block.Value().Val})

	// Add the block to the chain
	bm.bc.Add(block)
	return nil
}
