package txn

import (
	"container/list"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/truxen-org/chainpoc/txnchain"
	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
	"github.com/truxen-org/chainpoc/txnwire"
)

func eachPeer(peers *list.List, callback func(*Peer, *list.Element)) {
	// Loop thru the peers and close them (if we had them)
	for e := peers.Front(); e != nil; e = e.Next() {
		if peer, ok := e.Value.(*Peer); ok {
			callback(peer, e)
		}
	}
}

const (
	processReapingTimeout = 60 // TODO increase
	maxPeers              = 5
)

type Txn struct {
	// Channel for shutting down the txn
	shutdownChan   chan bool
	quit           chan bool
	CatchingupChan chan bool
	// DB interface
	//db *txndb.LDBDatabase
	db txnutil.Database
	// Block manager for processing new blocks and managing the block chain
	BlockManager *txnchain.BlockManager
	// The transaction pool. Transaction can be pushed on this pool
	// for later including in the blocks
	TxPool *txnchain.TxPool
	// Peers (NYI)
	peers *list.List
	// Nonce
	Nonce uint64

	Addr net.Addr
	Port int

	peerMut sync.Mutex

	// Capabilities for outgoing peers
	serverCaps Caps

	nat NAT
}

func New(cn txnchain.Consensus) (*Txn, error) {
	var nat NAT
	var err error
	if txnutil.Config.UseUPnP {
		nat, err = Discover()
		if err != nil {
			txnutil.Log.Debugln("UPnP failed", err)
		}
	}
	nonce, _ := txnutil.RandomUint64()
	txn := &Txn{
		shutdownChan:   make(chan bool),
		quit:           make(chan bool),
		CatchingupChan: make(chan bool),
		db:             txndb.DB,
		peers:          list.New(),
		Nonce:          nonce,
		serverCaps:     CapDefault,
		nat:            nat,
		Port:           txnutil.Config.OutboundPort,
	}
	txn.TxPool = txnchain.NewTxPool()
	txn.TxPool.Speaker = txn
	txn.BlockManager = txnchain.NewBlockManager(txn, cn)

	txn.TxPool.BlockManager = txn.BlockManager
	txn.BlockManager.TransactionPool = txn.TxPool

	// Start the tx pool
	txn.TxPool.Start()

	return txn, nil
}

func (s *Txn) AddPeer(conn net.Conn) {
	peer := NewPeer(conn, s, true)
	txnutil.Log.Debugf("adding new peer: %v", peer)
	if peer != nil && s.peers.Len() < maxPeers {
		s.peers.PushBack(peer)
		peer.Start()
	}
}

func (s *Txn) ProcessPeerList(addrs []string) {
	for _, addr := range addrs {
		// TODO Probably requires some sanity checks
		s.ConnectToPeer(addr)
	}
}

func (s *Txn) ConnectToPeer(addr string) error {
	if s.peers.Len() < maxPeers {
		var alreadyConnected bool

		eachPeer(s.peers, func(p *Peer, v *list.Element) {
			if p.conn == nil {
				return
			}
			phost, _, _ := net.SplitHostPort(p.conn.RemoteAddr().String())
			ahost, _, _ := net.SplitHostPort(addr)

			if phost == ahost {
				alreadyConnected = true
				return
			}
		})

		if alreadyConnected {
			return nil
		}

		peer := NewOutboundPeer(addr, s, s.serverCaps)

		s.peers.PushBack(peer)

		log.Printf("[SERV] Adding peer %s, %d / %d\n", addr, s.peers.Len(), maxPeers)
	}

	return nil
}

func (s *Txn) OutboundPeers() []*Peer {
	// Create a new peer slice with at least the length of the total peers
	outboundPeers := make([]*Peer, s.peers.Len())
	length := 0
	eachPeer(s.peers, func(p *Peer, e *list.Element) {
		if !p.inbound && p.conn != nil {
			outboundPeers[length] = p
			length++
		}
	})

	return outboundPeers[:length]
}

// func (s *Txn) InboundPeers() []*Peer {
// 	// Create a new peer slice with at least the length of the total peers
// 	inboundPeers := make([]*Peer, s.peers.Len())
// 	length := 0
// 	eachPeer(s.peers, func(p *Peer, e *list.Element) {
// 		if p.inbound {
// 			inboundPeers[length] = p
// 			length++
// 		}
// 	})

// 	return inboundPeers[:length]
// }

func (s *Txn) InOutPeers() []*Peer {
	// Reap the dead peers first
	s.reapPeers()

	// Create a new peer slice with at least the length of the total peers
	inboundPeers := make([]*Peer, s.peers.Len())
	length := 0
	eachPeer(s.peers, func(p *Peer, e *list.Element) {
		// Only return peers with an actual ip
		if len(p.host) > 0 {
			inboundPeers[length] = p
			length++
		}
	})

	return inboundPeers[:length]
}

func (s *Txn) Broadcast(msgType txnwire.MsgType, data []interface{}) {
	msg := txnwire.NewMessage(msgType, data)
	s.BroadcastMsg(msg)
}

func (s *Txn) BroadcastMsg(msg *txnwire.Msg) {
	eachPeer(s.peers, func(p *Peer, e *list.Element) {
		p.QueueMessage(msg)
	})
}

func (s *Txn) Peers() *list.List {
	return s.peers
}

func (s *Txn) reapPeers() {
	s.peerMut.Lock()
	defer s.peerMut.Unlock()

	eachPeer(s.peers, func(p *Peer, e *list.Element) {
		if atomic.LoadInt32(&p.disconnect) == 1 || (p.inbound && (time.Now().Unix()-p.lastPong) > int64(5*time.Minute)) {
			s.peers.Remove(e)
		}
	})
}

func (s *Txn) ReapDeadPeerHandler() {
	reapTimer := time.NewTicker(processReapingTimeout * time.Second)

	for {
		select {
		case <-reapTimer.C:
			s.reapPeers()
		}
	}
}

// Start the txn
func (s *Txn) Start() {
	// Bind to addr and port
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(s.Port))
	if err != nil {
		log.Println("Connection listening disabled. Acting as client", err)
	} else {
		// Starting accepting connections
		txnutil.Log.Infoln("Ready and accepting connections", ln.Addr())
		// Start the peer handler
		go s.peerHandler(ln)
	}

	if s.nat != nil {
		go s.upnpUpdateThread()
	}

	// Start the reaping processes
	go s.ReapDeadPeerHandler()

	// if txnutil.Config.Seed {
	// 	txnutil.Log.Debugln("Seeding")
	// 	// Testnet seed bootstrapping
	// 	resp, err := http.Get("http://www.txn.org/servers.poc3.txt")
	// 	if err != nil {
	// 		log.Println("Fetching seed failed:", err)
	// 		return
	// 	}
	// 	defer resp.Body.Close()
	// 	body, err := ioutil.ReadAll(resp.Body)
	// 	if err != nil {
	// 		log.Println("Reading seed failed:", err)
	// 		return
	// 	}

	// 	s.ConnectToPeer(string(body))
	// }
}

func (s *Txn) peerHandler(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			txnutil.Log.Debugln(err)

			continue
		}

		go s.AddPeer(conn)
	}
}

func (s *Txn) Stop() {
	// Close the database
	defer s.db.Close()
	//debug
	s.BlockManager.BlockChain().PrintLocalChain()
	eachPeer(s.peers, func(p *Peer, e *list.Element) {
		p.Stop()
	})

	close(s.quit)

	s.TxPool.Stop()
	s.BlockManager.Stop()

	close(s.shutdownChan)
}

// This function will wait for a shutdown and resumes main thread execution
func (s *Txn) WaitForShutdown() {
	<-s.shutdownChan
}

func (s *Txn) upnpUpdateThread() {
	// Go off immediately to prevent code duplication, thereafter we renew
	// lease every 15 minutes.
	timer := time.NewTimer(0 * time.Second)
	lport := s.Port
	first := true
out:
	for {
		select {
		case <-timer.C:
			var err error
			_, err = s.nat.AddPortMapping("TCP", int(lport), int(lport), "eth listen port", 20*60)
			if err != nil {
				txnutil.Log.Debugln("can't add UPnP port mapping:", err)
				break out
			}
			if first && err == nil {
				_, err = s.nat.GetExternalAddress()
				if err != nil {
					txnutil.Log.Debugln("UPnP can't get external address:", err)
					continue out
				}
				first = false
			}
			timer.Reset(time.Minute * 15)
		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	if err := s.nat.DeletePortMapping("TCP", int(lport), int(lport)); err != nil {
		txnutil.Log.Debugln("unable to remove UPnP port mapping:", err)
	} else {
		txnutil.Log.Debugln("succesfully disestablished UPnP port mapping")
	}
}
