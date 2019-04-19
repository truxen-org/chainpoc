package main

import (
	"fmt"
	"log"
	"time"

	"github.com/truxen-org/chainpoc/txn"
	"github.com/truxen-org/chainpoc/txnchain"
	"github.com/truxen-org/chainpoc/txnutil"
)

const timerInterval = 8

type Miner struct {
	coinbase  []byte
	txn       *txn.Txn
	consensus txnchain.Consensus
	resultCh  chan *txnchain.Block
	startCh   chan struct{}
	exitCh    chan struct{}
	skipCh    chan struct{}
	txCh      chan txnchain.TxMsg
	isMining  bool
	isSyncing bool
}

func NewMiner(txn *txn.Txn, cons txnchain.Consensus) *Miner {
	addr := getCoinbase()
	miner := &Miner{
		coinbase:  addr,
		txn:       txn,
		consensus: cons,
		resultCh:  make(chan *txnchain.Block),
		startCh:   make(chan struct{}),
		exitCh:    make(chan struct{}),
		skipCh:    make(chan struct{}),
		txCh:      make(chan txnchain.TxMsg),
		isSyncing: true,
	}
	go miner.startLoop()
	go miner.resultLoop()
	go miner.CatchingupHandler()
	return miner
}

func (m *Miner) MineOne() {
	header := m.txn.BlockManager.BlockChain().CreateHeader(m.coinbase)
	txnutil.Log.Debugf("\n\n>>>>>>>>>>>>>>>>>>Start Prepare Block with Header #%d", header.Number)
	var (
		goon bool
		err  error
	)
	goon, err = m.consensus.Prepare(header, m.skipCh)
	if err != nil {
		m.isMining = false
		log.Println(err)
		return
	}
	if !goon {
		m.isMining = false
		return
	}
	// Apply all transactions to the block
	txs := m.txn.TxPool.Flush()
	// log.Printf("Root %x \n", block.State().Root)
	// cb := m.txn.BlockManager.BlockChain().CurrentBlock
	block := txnchain.NewBlock(header)
	txnutil.Log.Debugln(">>>>>>>>>>>>>>>>>>Start applying transactions ...")
	start := time.Now()
	recepts, err := m.txn.BlockManager.ApplyTransactions(block, txs)
	txnutil.Log.Debugln(">>>>>>>>>>>>>>>>>>Applying transactions took", time.Since(start))
	if err != nil {
		log.Printf("error applying txs: %v", err)
	}
	// fm, _ := os.Create("memprofile")
	// pprof.WriteHeapProfile(fm)
	// fm.Close()
	// log.Debugf("Root after ApplyTransactions %x \n", cb.State().Root)
	if err := m.txn.BlockManager.BlockChain().AccumelateRewards(block, block); err != nil {
		log.Printf("error AccumelateRewards: %v", err)
	}
	// log.Printf("Root after AccumelateRewards %x \n", cb.State().Root)
	m.consensus.Finalize(block, txs, recepts)
	if err := m.consensus.Seal(block, m.resultCh, m.skipCh); err != nil {
		block.Undo()
		log.Printf("error Sealing block: %v", err)
		m.isMining = false
	}
}
func (m *Miner) CatchingupHandler() {
	for {
		select {
		case syncing := <-m.txn.CatchingupChan:
			txnutil.Log.Debugln("Received syncing ", syncing)
			m.isSyncing = syncing
			if syncing && m.isMining {
				m.skipCh <- struct{}{}
				txnutil.Log.Debugln("Done send skipCh")
				m.isMining = false
			}
		case <-m.exitCh:
			return
		}
	}
}

func (m *Miner) resultLoop() {
	for {
		select {
		case block := <-m.resultCh:
			fmt.Printf(" -------------------------- MINED BLOCK #%d ----------\n%v", block.Header().Number, block)
			fmt.Printf(" -------------------------- BLOCK #%d END ------------\n\n", block.Header().Number)
			m.txn.BlockManager.AfterMined(block)
			m.isMining = false
		case <-m.exitCh:
			return
			// default:
			// 	log.Println("got to update default")
		}
	}
}
//miner's scheduler
func (m *Miner) startLoop() {
	timesTrying := 0
	timer := time.NewTimer(0)
	<-timer.C
out:
	for {
		select {
		case tx := <-m.txCh:
			if txnutil.Config.StartMiningOnTx && tx.Type == txnchain.TxPre && !m.isMining {
				go m.Start()
			}
		case <-m.startCh: //start mine
			if m.isSyncing { //sync block
				timesTrying++
				if timesTrying > 3 {
					m.isSyncing = false
					log.Println("too long waiting syncing, break...")
				}
				txnutil.Log.Debugln("Network syncing, will start miner afterwards")
				timer.Reset(time.Second * time.Duration(timerInterval))
				continue out
			}
			timesTrying = 0
			if m.isMining {
				txnutil.Log.Debugln("Still mining...")
				timer.Reset(time.Second * time.Duration(timerInterval))
				continue out
			}
			m.isMining = true
			go m.MineOne()
			if txnutil.Config.StartMining {
				timer.Reset(time.Second * time.Duration(timerInterval))
				// timer.Reset(time.Second * time.Duration(txnutil.Config.Period))
			}
		case <-timer.C:
			if txnutil.Config.StartMining {
				go m.Start()
			}
		case <-m.exitCh:
			return
			// default:
			// 	log.Println("got to update default")
		}
	}
}

func (m *Miner) Start() {
	m.startCh <- struct{}{}
	// log.Println("Miner started")
}

func (m *Miner) Stop() {
	<-m.startCh
	log.Println("Miner stoped.")
}
func (m *Miner) Exit() {
	close(m.exitCh)
}
