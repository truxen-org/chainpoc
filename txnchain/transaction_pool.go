package txnchain

import (
	"container/list"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/truxen-org/chainpoc/txnutil"
	"github.com/truxen-org/chainpoc/txnwire"
)

const (
	txPoolQueueSize = 50000
)

type TxPoolHook chan *Transaction
type TxMsgTy byte

const (
	TxPre = iota
	TxPost
)

type TxMsg struct {
	Tx   *Transaction
	Type TxMsgTy
}

type PublicSpeaker interface {
	Broadcast(msgType txnwire.MsgType, data []interface{})
}

type TxProcessor interface {
	ProcessTransaction(tx *Transaction)
}

type txSender struct {
	tx     *Transaction
	hash   string
	sender []byte
}

// The tx pool a thread safe transaction pool handler. In order to
// guarantee a non blocking pool we use a queue channel which can be
// independently read without needing access to the actual pool. If the
// pool is being drained or synced for whatever reason the transactions
// will simple queue up and handled when the mutex is freed.
type TxPool struct {
	//server *Server
	Speaker PublicSpeaker
	// The mutex for accessing the Tx pool.
	mutex sync.Mutex
	// Queueing channel for reading and writing incoming
	// transactions to
	queueChan chan *Transaction
	// Quiting channel
	quit chan bool
	// The actual pool
	pool *list.List

	senders map[string][]byte

	BlockManager *BlockManager

	SecondaryProcessor TxProcessor

	subscribers []chan TxMsg

	senderChan chan txSender
}

func NewTxPool() *TxPool {
	return &TxPool{
		//server:    s,
		mutex:      sync.Mutex{},
		pool:       list.New(),
		senders:    make(map[string][]byte),
		queueChan:  make(chan *Transaction, txPoolQueueSize),
		quit:       make(chan bool),
		senderChan: make(chan txSender, txPoolQueueSize),
	}
}

func (pool *TxPool) getSender(hash string) []byte {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	return pool.senders[hash]
}

// Blocking function. Don't use directly. Use QueueTransaction instead
func (pool *TxPool) addTransaction(tx_sender txSender) {
	pool.mutex.Lock()
	pool.pool.PushBack(tx_sender.tx)
	pool.senders[tx_sender.hash] = tx_sender.sender
	// log.Printf("add sender %s %x", hash, sender)
	pool.mutex.Unlock()
	if txnutil.Config.IsMiner == false {
		// Broadcast the transaction to the rest of the peers
		pool.Speaker.Broadcast(txnwire.MsgTxTy, []interface{}{tx_sender.tx.RlpData()})
	}
}

// Process transaction validates the Tx and processes funds from the
// sender to the recipient.
func (pool *TxPool) ProcessTransaction(senderAddr []byte, tx *Transaction, block *Block) (receipt *Receipt, err error) {
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		log.Println(r)
	// 		err = fmt.Errorf("%v", r)
	// 	}
	// }()
	ass := NewAddrStateStore()
	sender := block.GetAddr(senderAddr)
	var failed bool
	// Make sure there's enough in the sender's account. Having insufficient
	// funds won't invalidate this transaction but simple ignores it.
	totAmount := new(big.Int).Add(tx.Value, new(big.Int).Mul(TxFee, TxFeeRat))
	if sender.Amount.Cmp(totAmount) < 0 {
		log.Printf("[TXPL] Error ProcessTransaction: insufficient amount in sender's (%x) account", senderAddr)
		failed = true
	}

	// if sender.Nonce != tx.Nonce {
	// 	log.Printf("[TXPL] Error ProcessTransaction: %v", fmt.Errorf("Invalid nonce %d(%d)", tx.Nonce, sender.Nonce))
	// 	failed = true
	// }
	// start := time.Now()
	sender.Nonce += 1
	if !failed {
		// Get the receiver
		receiver := block.GetAddr(tx.Recipient)
		txnutil.Log.Debugf("receiver: %s value %v\n", hex.EncodeToString(tx.Recipient), tx.Value)
		// Send Tx to self
		// if bytes.Compare(tx.Recipient, senderAddr) == 0 {
		// 	// Subtract the fee
		// 	sender.Amount.Sub(sender.Amount, new(big.Int).Mul(TxFee, TxFeeRat))
		// } else {
		// Subtract the amount from the senders account
		sender.Amount.Sub(sender.Amount, totAmount)

		// Add the amount to receivers account which should conclude this transaction
		receiver.Amount.Add(receiver.Amount, tx.Value)

		block.UpdateAddr(tx.Recipient, receiver)
		ass.Add(tx.Recipient, receiver)
		// }

		block.UpdateAddr(senderAddr, sender)
		ass.Add(senderAddr, sender)

	}

	receipt = NewReceipt(tx.Hash(), block.header.state.Root.([]byte), failed)
	receipt.SetAddressStates(ass) //receipt contains transaction result for single execution model purpose
	txnutil.Log.Debugf("[TXPL] Processed Tx %x, Rt %x\n", tx.Hash(), receipt.Hash())

	// Notify the subscribers
	pool.notifySubscribers(TxPost, tx)
	// fmt.Println("++++++++++++++++++++++ end ", time.Since(start))
	return
}

//quick validation for transaction before add to tx pool
func (pool *TxPool) ValidateTransaction(senderAddr []byte, tx *Transaction) error {
	// Get the last block so we can retrieve the sender and receiver from
	// the merkle trie
	block := pool.BlockManager.BlockChain().CurrentBlock
	// Something has gone horribly wrong if this happens
	if block == nil {
		return errors.New("No last block on the block chain")
	}

	// Get the sender
	accountState := pool.BlockManager.GetAddrState(senderAddr)
	sender := accountState.Account

	totAmount := new(big.Int).Add(tx.Value, new(big.Int).Mul(TxFee, TxFeeRat))
	// Make sure there's enough in the sender's account. Having insufficient
	// funds won't invalidate this transaction but simple ignores it.
	if sender.Amount.Cmp(totAmount) < 0 {
		log.Printf("[TXPL] total amount needed: %v\n", totAmount)
		return fmt.Errorf("[TXPL] Insufficient amount in sender's (%x) account", tx.Sender())
	}

	// Increment the nonce making each tx valid only once to prevent replay
	// attacks

	return nil
}
//process tx inbound
func (pool *TxPool) senderHandler() {

out:
	for {
		select {
		case tx_sender := <-pool.senderChan:
			// log.Printf("tx_sender = %v", tx_sender)
			// Validate the transaction
			err := pool.ValidateTransaction(tx_sender.sender, tx_sender.tx)
			if err != nil {
				if txnutil.Config.Debug {
					log.Println("Validating Tx failed", err)
				}
			} else {
				// Call blocking version. At this point it
				// doesn't matter since this is a goroutine
				pool.addTransaction(tx_sender)

				// Notify the subscribers
				pool.notifySubscribers(TxPre, tx_sender.tx)
			}
		case <-pool.quit:
			break out
		}
	}
}

func (pool *TxPool) queueHandler() {
out:
	for {
		select {
		case tx := <-pool.queueChan:
			go func(tx *Transaction) {
				hash := txnutil.Hex(tx.Hash())
				if pool.getSender(hash) != nil {
					return
				}
				sender := tx.Sender()
				// log.Printf("sender = %x", sender)
				pool.senderChan <- txSender{tx, hash, sender}
			}(tx)
		case <-pool.quit:
			break out
		}
	}
}

func (pool *TxPool) QueueTransaction(tx *Transaction) {
	pool.queueChan <- tx
}
//get all transactions from pool
func (pool *TxPool) Flush() []*Transaction {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()

	txList := make([]*Transaction, pool.pool.Len())
	i := 0
	for e := pool.pool.Front(); e != nil; e = e.Next() {
		if tx, ok := e.Value.(*Transaction); ok {
			txList[i] = tx
		}

		i++
	}

	// Recreate a new list all together
	// XXX Is this the fastest way?
	pool.pool = list.New()
	// pool.senders = make(map[string][]byte)
	return txList
}

func (pool *TxPool) Start() {
	go pool.queueHandler()
	go pool.senderHandler()
}

func (pool *TxPool) Stop() {
	log.Println("[TXP] Stopping...")

	close(pool.quit)

	pool.Flush()
}

func (pool *TxPool) Subscribe(channel chan TxMsg) {
	pool.subscribers = append(pool.subscribers, channel)
}

func (pool *TxPool) notifySubscribers(ty TxMsgTy, tx *Transaction) {
	msg := TxMsg{Type: ty, Tx: tx}
	for _, subscriber := range pool.subscribers {
		// log.Printf("[TXP] subscriber %v, %v", subscriber, msg)

		subscriber <- msg
	}
}
