package txn

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/truxen-org/chainpoc/txnchain"
	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
	"github.com/truxen-org/chainpoc/txnwire"
)

const (
	// The size of the output buffer for writing messages
	outputBufferSize = 50
)

type DiscReason byte

const (
	// Values are given explicitly instead of by iota because these values are
	// defined by the wire protocol spec; it is easier for humans to ensure
	// correctness when values are explicit.
	DiscReRequested  = 0x00
	DiscReTcpSysErr  = 0x01
	DiscBadProto     = 0x02
	DiscBadPeer      = 0x03
	DiscTooManyPeers = 0x04
	DiscConnDup      = 0x05
	DiscGenesisErr   = 0x06
	DiscProtoErr     = 0x07
)

var discReasonToString = []string{
	"Disconnect requested",
	"Disconnect TCP sys error",
	"Disconnect bad protocol",
	"Disconnect useless peer",
	"Disconnect too many peers",
	"Disconnect already connected",
	"Disconnect wrong genesis block",
	"Disconnect incompatible network",
}

func (d DiscReason) String() string {
	if len(discReasonToString) > int(d) {
		return "Unknown"
	}

	return discReasonToString[d]
}

// Peer capabilities
type Caps byte

const (
	CapPeerDiscTy = 1 << iota
	CapTxTy
	CapChainTy
	CapDefault = CapChainTy | CapTxTy
	// CapDefault = CapChainTy | CapTxTy | CapPeerDiscTy
)

var capsToString = map[Caps]string{
	CapPeerDiscTy: "Peer discovery",
	CapTxTy:       "Transaction relaying",
	CapChainTy:    "Block chain relaying",
}

func (c Caps) IsCap(cap Caps) bool {
	return c&cap > 0
}

func (c Caps) String() string {
	var caps []string
	if c.IsCap(CapPeerDiscTy) {
		caps = append(caps, capsToString[CapPeerDiscTy])
	}
	if c.IsCap(CapChainTy) {
		caps = append(caps, capsToString[CapChainTy])
	}
	if c.IsCap(CapTxTy) {
		caps = append(caps, capsToString[CapTxTy])
	}
	return strings.Join(caps, " | ")
}

type DoneEvent struct{}
type StartEvent struct{}

type Peer struct {
	// Txn interface
	txn *Txn
	// Net connection
	conn net.Conn
	// Output queue which is used to communicate and handle messages
	outputQueue chan *txnwire.Msg
	// Quit channel
	quit chan bool
	// Determines whether it's an inbound or outbound peer
	inbound bool
	// Flag for checking the peer's connectivity state
	connected  int32
	disconnect int32
	// Last known message send
	lastSend time.Time
	// Indicated whether a verack has been send or not
	// This flag is used by writeMessage to check if messages are allowed
	// to be send or not. If no version is known all messages are ignored.
	versionKnown bool

	// Last received pong message
	lastPong int64
	// Indicates whether a MsgGetPeersTy was requested of the peer
	// this to prevent receiving false peers.
	requestedPeerList bool

	host []interface{}
	port int
	caps Caps

	pubkey []byte

	// Indicated whether the node is catching up or not
	catchingUp bool

	Version string
}

func NewPeer(conn net.Conn, txn *Txn, inbound bool) *Peer {
	data, _ := txndb.DB.Get([]byte("KeyRing"))
	pubkey := txnutil.NewValueFromBytes(data).Get(2).Bytes()

	return &Peer{
		outputQueue: make(chan *txnwire.Msg, outputBufferSize),
		quit:        make(chan bool),
		txn:         txn,
		conn:        conn,
		inbound:     inbound,
		disconnect:  0,
		connected:   1,
		port:        txnutil.Config.OutboundPort,
		pubkey:      pubkey,
	}
}

func NewOutboundPeer(addr string, txn *Txn, caps Caps) *Peer {

	p := &Peer{
		outputQueue: make(chan *txnwire.Msg, outputBufferSize),
		quit:        make(chan bool),
		txn:         txn,
		inbound:     false,
		connected:   0,
		disconnect:  0,
		caps:        caps,
		Version:     fmt.Sprintf("/Txn(G) v%s/%s", txnutil.Config.Ver, runtime.GOOS),
	}

	// Set up the connection in another goroutine so we don't block the main thread
	go func() {
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)

		if err != nil {
			txnutil.Log.Debugln("Connection to peer failed", err)
			p.Stop()
			txn.CatchingupChan <- false
			return
		}
		p.conn = conn

		// Atomically set the connection state
		atomic.StoreInt32(&p.connected, 1)
		atomic.StoreInt32(&p.disconnect, 0)

		p.Start()
	}()

	return p
}

// Outputs any RLP encoded data to the peer
func (p *Peer) QueueMessage(msg *txnwire.Msg) {
	p.outputQueue <- msg
}

func (p *Peer) writeMessage(msg *txnwire.Msg) {
	// Ignore the write if we're not connected
	if atomic.LoadInt32(&p.connected) != 1 {
		return
	}

	if !p.versionKnown {
		switch msg.Type {
		case txnwire.MsgHandshakeTy: // Ok
		default: // Anything but ack is allowed
			return
		}
	}

	err := txnwire.WriteMessage(p.conn, msg)
	if err != nil {
		txnutil.Log.Debugln("[PEER]Can't send message:", err)
		// Stop the client if there was an error writing to it
		p.Stop()
		return
	}
	txnutil.Log.Debugln("[PEER]send message:", msg.Type)
}

// Outbound message handler. Outbound messages are handled here
func (p *Peer) HandleOutbound() {
	// The ping timer. Makes sure that every 2 minutes a ping is send to the peer
	pingTimer := time.NewTicker(2 * time.Minute)
	serviceTimer := time.NewTicker(5 * time.Minute)

out:
	for {
		select {
		// Main message queue. All outbound messages are processed through here
		case msg := <-p.outputQueue:
			p.writeMessage(msg)

			p.lastSend = time.Now()

		// Ping timer sends a ping to the peer each 2 minutes
		case <-pingTimer.C:
			p.writeMessage(txnwire.NewMessage(txnwire.MsgPingTy, ""))

		// Service timer takes care of peer broadcasting, transaction
		// posting or block posting
		case <-serviceTimer.C:
			if p.caps&CapPeerDiscTy > 0 {
				msg := p.peersMessage()
				p.txn.BroadcastMsg(msg)
			}

		case <-p.quit:
			// Break out of the for loop if a quit message is posted
			break out
		}
	}

clean:
	// This loop is for draining the output queue and anybody waiting for us
	for {
		select {
		case <-p.outputQueue:
			// TODO
		default:
			break clean
		}
	}
}

// Inbound handler. Inbound messages are received here and passed to the appropriate methods
func (p *Peer) HandleInbound() {

	for atomic.LoadInt32(&p.disconnect) == 0 {
		// HMM?
		time.Sleep(500 * time.Millisecond)

		// Wait for a message from the peer
		msgs, err := txnwire.ReadMessages(p.conn)
		if err != nil {
			txnutil.Log.Debugln(err)
		}
		for _, msg := range msgs {
			txnutil.Log.Debugf("handleInbound msg %v: %d", msg.Type, msg.Data.Len())
			switch msg.Type {
			case txnwire.MsgHandshakeTy:
				// Version message
				p.handleHandshake(msg)

				if p.caps.IsCap(CapPeerDiscTy) {
					p.QueueMessage(txnwire.NewMessage(txnwire.MsgGetPeersTy, ""))
				}
			case txnwire.MsgDiscTy:
				p.Stop()
				txnutil.Log.Infoln("Disconnect peer:", msg.Data.Get(0))
			case txnwire.MsgPingTy:
				// Respond back with pong
				p.QueueMessage(txnwire.NewMessage(txnwire.MsgPongTy, ""))
			case txnwire.MsgPongTy:
				// If we received a pong back from a peer we set the
				// last pong so the peer handler knows this peer is still
				// active.
				p.lastPong = time.Now().Unix()
			case txnwire.MsgBlockTy:
				go p.receiveBlock(msg.Data)
				p.catchingUp = false
			case txnwire.MsgTxTy:
				// If the message was a transaction queue the transaction
				// in the TxPool where it will undergo validation and
				// processing when a new block is found
				for i := 0; i < msg.Data.Len(); i++ {
					tx := txnchain.NewTransactionFromData(msg.Data.Get(i).Encode())
					hash := tx.Hash()
					txnutil.Log.Infof("[PEER] Received tx %d: %x\n", i, hash)
					p.txn.TxPool.QueueTransaction(tx)
				}
			case txnwire.MsgGetPeersTy:
				// Flag this peer as a 'requested of new peers' this to
				// prevent malicious peers being forced.
				p.requestedPeerList = true
				// Peer asked for list of connected peers
				p.pushPeers()
			case txnwire.MsgPeersTy:
				// Received a list of peers (probably because MsgGetPeersTy was send)
				// Only act on message if we actually requested for a peers list
				//if p.requestedPeerList {
				data := msg.Data
				// Create new list of possible peers for the txn to process
				peers := make([]string, data.Len())
				// Parse each possible peer
				for i := 0; i < data.Len(); i++ {
					value := data.Get(i)
					peers[i] = unpackAddr(value.Get(0), value.Get(1).Uint())
				}

				// Connect to the list of peers
				p.txn.ProcessPeerList(peers)
				// Mark unrequested again
				p.requestedPeerList = false

				//}
			case txnwire.MsgGetChainTy:
				var parent *txnchain.Block
				// Length minus one since the very last element in the array is a count
				l := msg.Data.Len() - 1
				// Ignore empty get chains
				if l == 0 {
					break
				}
				// Amount of parents in the canonical chain
				amountOfBlocks := msg.Data.Get(l).Uint()
				// amountOfBlocks := uint64(100)
				// Check each SHA block hash from the message and determine whether
				// the SHA is in the database
				for i := 0; i < l; i++ {
					txnutil.Log.Debugf("received MsgGetChainTy [%d], %x", i, msg.Data.Get(i).Raw())
					if data := msg.Data.Get(i).Bytes(); p.txn.BlockManager.BlockChain().HasBlock(data) {
						parent = p.txn.BlockManager.BlockChain().GetBlock(data)
						txnutil.Log.Debugf("[PEER]find block #%d: %x... ", parent.Header().Number, parent.Hash()[:2])
						break
					}
				}

				// If a parent is found send back a reply
				if parent != nil {
					chain := p.txn.BlockManager.BlockChain().GetChainFromHash(parent.Hash(), amountOfBlocks)
					txnutil.Log.Debugf("[PEER]chain len %d ", len(chain))
					if len(chain) > 0 {
						p.QueueMessage(txnwire.NewMessage(txnwire.MsgBlockTy, chain))
					}
				} else {
					// If no blocks are found we send back a reply with msg not in chain
					// and the last hash from get chain
					lastHash := msg.Data.Get(l - 1)
					txnutil.Log.Debugf("[PEER]Sending not in chain with hash %x\n", lastHash.Raw())
					p.QueueMessage(txnwire.NewMessage(txnwire.MsgNotInChainTy, []interface{}{lastHash.Raw()}))
				}
			case txnwire.MsgNotInChainTy:
				txnutil.Log.Infof("[PEER]Get Not in chain %x\n", msg.Data.Get(0).Raw())
				// TODO
				p.requestChainFromPrev()
				// Unofficial but fun nonetheless
			case txnwire.MsgTalkTy:
				txnutil.Log.Infof("%v says: %s\n", p.conn.RemoteAddr(), msg.Data.Str())

			// If a new miner joins
			case txnwire.MsgPropTy:
				if txnutil.Config.IsMiner {
					data := msg.Data.Get(0)
					// log.Println("propose data", data)
					pr := &txnchain.ProposalRequest{}
					pr.RlpValueDecode(data)
					log.Println("[PEER]received Proposal", pr)
					if err := p.txn.BlockManager.Cnsnss.Propose(pr); err != nil {
						log.Println("propose signer failed", err)
					}
					// p.txn.BroadcastMsg(msg)//will cause dead lock
				}
			}

		}
	}

	p.Stop()
}

func (p *Peer) receiveBlock(data *txnutil.Value) {

	if txnutil.Config.IsMiner {
		//<-p.txn.CatchingupChan
		p.txn.CatchingupChan <- true

		defer func() {
			p.txn.CatchingupChan <- false
			txnutil.Log.Debugln("[PEER]p.txn.CatchingupChan <- false")
		}()
	}
	// Get all blocks and process them
	var block, lastBlock *txnchain.Block
	var err error
	for i := data.Len() - 1; i >= 0; i-- {
		block = txnchain.NewBlockFromRlpValue(data.Get(i))
		// hash := block.Hash()
		txnutil.Log.Infof("[PEER]Received block: %v", block)
		// txnutil.Log.Infof("[PEER]Received block#%d: %x... df=%d", block.Header().Number, block.Hash()[:3], block.Header().Difficulty)

		// txnutil.Log.Infof("[PEER] Received block: %v", block.Header().Number)
		// if p.txn.BlockManager.BlockChain().HasBlock(hash) {
		// 	txnutil.Log.Debugf("[PEER] Block hash %x exists\n", hash)
		// 	continue
		// }
		// if p.txn.BlockManager.BlockChain().CurrentBlock.Header().Number >= block.Header().Number {
		// 	txnutil.Log.Debugf("[PEER] Block #%v exists\n", block.Header().Number)
		// 	continue
		// }
		err = p.txn.BlockManager.ProcessBlock(block)
		if err != nil {
			txnutil.Log.Infof("[PEER] Process block #%d error: %v\n", block.Header().Number, err)
			break
		} else {
			lastBlock = block
		}
	}

	if err != nil {
		// If the parent is unknown try to catch up with this peer
		if txnchain.IsParentErr(err) {
			txnutil.Log.Infoln("[PEER] Parent unknown; will catching up..")
			// p.catchingUp = false //CatchupWithPeer() need this.
			// p.CatchupWithPeer()
			p.requestChainFromPrev()
			return
		}
		if txnchain.IsValidationErr(err) {
			txnutil.Log.Infoln("[PEER] Validation Err:", err)
			if txnchain.IsTrustErr(err) {
				txnutil.Log.Infoln("[PEER] Trust Err:", err)
				if txnutil.Config.IsMiner {
					signerS := txnchain.SignerFromPubKey(block.Header().PubKey)
					pr := &txnchain.ProposalRequest{
						Prop: &txnchain.Proposal{
							Signer: txnutil.FromHex(signerS),
							Nonce:  txnchain.NonceDropVote,
						},
					}
					if err := p.txn.BlockManager.Cnsnss.Propose(pr); err != nil {
						log.Println("propose signer drop failed", err)
					} else {
						log.Println("proposed signer drop", signerS)
					}
				}
			}
			// TODO
		}
		txnutil.Log.Infoln("[PEER] Other sync Err:", err)
	} else {
		// XXX Do we want to catch up if there were errors?
		// If we're catching up, try to catch up further.
		if p.catchingUp && data.Len() > 1 {
			if lastBlock != nil {
				blockInfo := lastBlock.BlockInfo()
				txnutil.Log.Infof("Synced to block height #%d %x %x\n", blockInfo.Number, lastBlock.Hash(), blockInfo.Hash)
			}
			// p.catchingUp = false
			// p.CatchupWithPeer()
		}
	}
}

func (p *Peer) requestChainFromPrev() {

	head := p.txn.BlockManager.BlockChain().CurrentBlock.Header()
	hash := head.PrevHash
	msg := txnwire.NewMessage(txnwire.MsgGetChainTy, []interface{}{hash, uint64(500)})
	p.QueueMessage(msg)
	txnutil.Log.Infof("[PEER]Requesting blockchain from #%d: %x...\n", head.Number-1, hash[:3])
}
func (p *Peer) Start() {

	log.Printf("Peer starting %v", p)
	peerHost, peerPort, _ := net.SplitHostPort(p.conn.LocalAddr().String())
	servHost, servPort, _ := net.SplitHostPort(p.conn.RemoteAddr().String())

	if p.inbound {
		p.host, p.port = packAddr(peerHost, peerPort)
	} else {
		p.host, p.port = packAddr(servHost, servPort)
	}

	err := p.pushHandshake()
	if err != nil {
		txnutil.Log.Debugln("Peer can't send outbound version ack", err)

		p.Stop()

		return
	}
	// Run the outbound handler in a new goroutine
	go p.HandleOutbound()
	// Run the inbound handler in a new goroutine
	go p.HandleInbound()

}

func (p *Peer) Stop() {
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	close(p.quit)
	if atomic.LoadInt32(&p.connected) != 0 {
		p.writeMessage(txnwire.NewMessage(txnwire.MsgDiscTy, []interface{}{p.conn.LocalAddr().String()}))
		p.conn.Close()
	}
}

func (p *Peer) pushHandshake() error {
	data, _ := txndb.DB.Get([]byte("KeyRing"))
	pubkey := txnutil.NewValueFromBytes(data).Get(2).Bytes()

	msg := txnwire.NewMessage(txnwire.MsgHandshakeTy, []interface{}{
		uint32(5), uint32(0), p.Version, byte(p.caps), p.port, pubkey,
	})

	p.QueueMessage(msg)

	return nil
}

func (p *Peer) peersMessage() *txnwire.Msg {
	outPeers := make([]interface{}, len(p.txn.InOutPeers()))
	// Serialise each peer
	for i, peer := range p.txn.InOutPeers() {
		outPeers[i] = peer.RlpData()
	}

	// Return the message to the peer with the known list of connected clients
	return txnwire.NewMessage(txnwire.MsgPeersTy, outPeers)
}

// Pushes the list of outbound peers to the client when requested
func (p *Peer) pushPeers() {
	p.QueueMessage(p.peersMessage())
}

func (p *Peer) handleHandshake(msg *txnwire.Msg) {
	c := msg.Data

	if c.Get(0).Uint() != 5 {
		txnutil.Log.Debugln("Invalid peer version. Require protocol v5")
		p.Stop()
		return
	}

	// [PROTOCOL_VERSION, NETWORK_ID, CLIENT_ID, CAPS, PORT, PUBKEY]
	p.versionKnown = true

	// If this is an inbound connection send an ack back
	if p.inbound {
		p.pubkey = c.Get(5).Bytes()
		p.port = int(c.Get(4).BigInt().Int64())

		// Self connect detection
		key := txndb.DB.GetKeys()[0]
		if bytes.Compare(key.PublicKey, p.pubkey) == 0 {
			p.Stop()

			return
		}
	} else {
		p.CatchupWithPeer()
	}

	// Set the peer's caps
	p.caps = Caps(c.Get(3).Byte())
	// Get a reference to the peers version
	p.Version = c.Get(2).Str()

	txnutil.Log.Debugln("[PEER]", p)
}

func (p *Peer) String() string {
	var strBoundType string
	if p.inbound {
		strBoundType = "inbound"
	} else {
		strBoundType = "outbound"
	}
	var strConnectType string
	if atomic.LoadInt32(&p.disconnect) == 0 {
		strConnectType = "connected"
	} else {
		strConnectType = "disconnected"
	}

	return fmt.Sprintf("[%s] (%s) %v %s [%s]", strConnectType, strBoundType, p.conn.RemoteAddr(), p.Version, p.caps)

}

func (p *Peer) CatchupWithPeer() {
	if !p.catchingUp {
		if txnutil.Config.IsMiner {
			//<-p.txn.CatchingupChan
			p.txn.CatchingupChan <- true
		}
		p.catchingUp = true
		cblock := p.txn.BlockManager.BlockChain().CurrentBlock
		hash := cblock.Hash()
		msg := txnwire.NewMessage(txnwire.MsgGetChainTy, []interface{}{hash, uint64(500)})
		p.QueueMessage(msg)
		txnutil.Log.Infof("[PEER]Requesting blockchain from local current #%d: %x...\n", cblock.Header().Number, hash[:3])
	}
}

func (p *Peer) RlpData() []interface{} {
	return []interface{}{p.host, p.port, p.pubkey}
}

func packAddr(address, port string) ([]interface{}, int) {
	addr := strings.Split(address, ".")
	a, _ := strconv.Atoi(addr[0])
	b, _ := strconv.Atoi(addr[1])
	c, _ := strconv.Atoi(addr[2])
	d, _ := strconv.Atoi(addr[3])
	host := []interface{}{int32(a), int32(b), int32(c), int32(d)}
	prt, _ := strconv.Atoi(port)

	return host, prt
}

func unpackAddr(value *txnutil.Value, p uint64) string {
	a := strconv.Itoa(int(value.Get(0).Uint()))
	b := strconv.Itoa(int(value.Get(1).Uint()))
	c := strconv.Itoa(int(value.Get(2).Uint()))
	d := strconv.Itoa(int(value.Get(3).Uint()))
	host := strings.Join([]string{a, b, c, d}, ".")
	port := strconv.Itoa(int(p))

	return net.JoinHostPort(host, port)
}
