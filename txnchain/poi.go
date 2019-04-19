package txnchain

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/truxen-org/chainpoc/txndb"
	"github.com/truxen-org/chainpoc/txnutil"
	lru "github.com/hashicorp/golang-lru"
)

const (
	missingRoundToDrop = 2                       //after how many times a signer has been found not mining it will be kicked out from the list
	inmemorySnapshots  = 8                       // Number of recent vote snapshots to keep in memory
	diffInTurn         = uint64(2)               // Block difficulty for in-turn signatures
	diffNoTurn         = uint64(1)               // Block difficulty for out-of-turn signatures
	checkpointInterval = 100                     //snapshot checkpoint
	period             = 10                      //seconds between blocks.
	SignerBytesLen     = 20                      //length of signer in bytes
	wiggleTime         = 4500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// Clique proof-of-authority protocol constants.
var (
	// epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	NonceAuthVote           = txnutil.FromHex("ffffffffffffffff") // Magic nonce number to vote on adding a new signer
	NonceDropVote           = txnutil.FromHex("0000000000000000") // Magic nonce number to vote on removing a signer.
	errNonContiguousHeaders = errors.New("non-contiguous headers")
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	ErrUnknownAncestor = errors.New("Error: unknown ancestor")
	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("Error: unauthorized signer")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
)

func sigHash(header *Header) []byte {
	value := txnutil.Encode([]interface{}{
		header.Number,
		header.Time,
		header.PrevHash,
		header.Coinbase,
		header.Extra,
		header.Nonce,
		header.PubKey,
		header.Difficulty,
		header.Signers,
		header.TxSha,
		header.ReceiptSha,
		header.state.Root,
	})
	return txnutil.Sha3Bin(value)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func CalcDifficulty(snap *Snapshot, signer string) uint64 {
	if snap.inturn(snap.Number+1, signer) {
		return diffInTurn
	}
	return diffNoTurn
}

//get signer label from public key
func SignerFromPubKey(pubkey []byte) string {
	bsigner := txnutil.Sha3Bin(pubkey[1:])[12:]
	signer := txnutil.Hex(bsigner)
	return signer
}
func SignerFromCert(cert []byte) (string, error) {

	certBytes, err := txnutil.ParseECPublicKeyFromBlockBytes(cert)
	if err != nil {
		return "", err
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(certBytes)
	if err != nil {
		return "", err
	}
	return SignerFromPubKey(keyBytes), nil
}

type ProposalRequest struct {
	Quoted, Signature, Certificate []byte
	Prop                           *Proposal
}

func (p *ProposalRequest) String() string {
	return fmt.Sprintf("\nSigner=%x\nAuth=%x\nQuoted=%x\nSignature=%x\nCertificate=%x", p.Prop.Signer, p.Prop.Nonce, p.Quoted, p.Signature, p.Certificate)
}

func (p *ProposalRequest) RlpValueEncode() *txnutil.Value {
	return txnutil.NewValue([]interface{}{p.Quoted, p.Signature, p.Certificate, p.Prop.Signer, p.Prop.Nonce})
}

func (p *ProposalRequest) RlpValueDecode(rlpValue *txnutil.Value) {
	p.Quoted = rlpValue.Get(0).Bytes()
	p.Signature = rlpValue.Get(1).Bytes()
	p.Certificate = rlpValue.Get(2).Bytes()
	prop := &Proposal{}
	prop.Signer = rlpValue.Get(3).Bytes()
	prop.Nonce = rlpValue.Get(4).Bytes()
	p.Prop = prop
}

type Proposal struct {
	Signer []byte
	Nonce  []byte //use NonceAuthVote and NonceDropVote for consistence and better serilization
}

func (prop *Proposal) String() string {
	return fmt.Sprintf("Proposal: Signer=%x, Nonce=%x", prop.Signer, prop.Nonce)
}

type Consensus interface {
	Prepare(header *Header, skipCh <-chan struct{}) (bool, error)
	Finalize(block *Block, txs []*Transaction, receipts []*Receipt)
	Seal(block *Block, results chan<- *Block, skipCh <-chan struct{}) error
	VerifyHeader(header *Header) error
	Propose(p *ProposalRequest) error
}

type PoI struct {
	period             uint64
	checkpointInterval uint64 // Number of blocks after which to save the vote snapshot to the database
	pubKey             []byte
	bc                 *BlockChain
	db                 txnutil.Database // Database to store and retrieve snapshot checkpoints
	recents            *lru.ARCCache    // Snapshots for recent block to speed up reorgs
	proposal           *Proposal
}

func NewPoI(key []byte) *PoI {
	recents, _ := lru.NewARC(inmemorySnapshots)
	return &PoI{
		period:             period,
		checkpointInterval: checkpointInterval,
		db:                 txndb.DB,
		pubKey:             key,
		recents:            recents,
	}
}
//process miner join request
func (c *PoI) Propose(pr *ProposalRequest) error {
	//no need to verify a drop proposal since it is from the node itself
	// log.Println("Start propose: ", pr)
	if bytes.Equal(pr.Prop.Nonce, NonceAuthVote) {
		if err := txnutil.PCRVerify(pr.Quoted); err != nil {
			log.Printf("PCRVerify error: %v", err)
			return err
		}
		if err := txnutil.CertificateVerify(pr.Certificate); err != nil {
			log.Printf("CertificateVerify error: %v\n", err)
			return err
		}
		pubkey, _ := txnutil.ParseECPublicKeyFromCertBlockBytes(pr.Certificate)
		if err := txnutil.SignatureVerify(pubkey, pr.Signature, pr.Quoted); err != nil {
			log.Printf("SignatureVerify error: %v", err)
			return err
		}
	}
	c.proposal = pr.Prop
	log.Printf("[POA][proposal]Proposed %v", c.proposal)
	return nil
}

func (c *PoI) Prepare(header *Header, skipCh <-chan struct{}) (bool, error) {
	log.Printf("[POA] Prepare c.pubKey= %x\n", c.pubKey)
	signer := SignerFromPubKey(c.pubKey)
	snap, err := c.snapshot(header.Number-1, header.PrevHash)
	if err != nil {
		return false, err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return false, errUnauthorizedSigner
	}
	for sigr := range snap.Signers {
		if snap.Number > snap.Signers[sigr].Last+uint64(len(snap.Signers)*missingRoundToDrop) {
			c.proposal = &Proposal{
				Signer: txnutil.FromHex(sigr),
				Nonce:  NonceDropVote,
			}
			// delete(snap.Signers, sigr)
			// log.Printf("[SNAP][proposal] dropped from signer list for inactive: %s, %v", sigr, snap)
		}
	}
	// log.Printf("[POA] Prepare #%d:  %v", header.Number, snap)
	log.Println("----------------")
	log.Printf("[POA] Prepare #%d", header.Number)
	if c.proposal != nil {
		log.Printf("[POA][proposal] Handling Proposal in Prepare: %v", c.proposal)
		pSigner := c.proposal.Signer
		ps := txnutil.Hex(pSigner)
		// log.Println("[proposal]P", snap.Signers[ps])
		authorized := snap.Signers[ps] != nil
		if bytes.Equal(c.proposal.Nonce, NonceAuthVote) {
			if authorized {
				log.Printf("[POA]Signer propose rejected: already in list: %s; ignore.", ps)
				snap.Proposal = nil
			} else {
				header.Extra = pSigner
				header.Nonce = NonceAuthVote
				log.Printf("[POA][proposal] Add proposal packed into block #%d: Extra=%x, Nonce=%x.", header.Number, header.Extra, header.Nonce)
			}
		} else if bytes.Equal(c.proposal.Nonce, NonceDropVote) {
			if authorized {
				header.Extra = pSigner
				header.Nonce = NonceDropVote
				// delete(snap.Signers, ps)
				// log.Println("[POA]snap.Signers deleted", ps)
				log.Printf("[POA][proposal] Drop proposal packed into block #%d: Extra=%x, Nonce=%x.", header.Number, header.Extra, header.Nonce)
			} else {
				log.Printf("[POA]Signer drop rejected: not in list: %s; ignore.", ps)
			}
		}
		c.proposal = nil
	}

	err = snap.checkRecent(signer, header.Number)
	if err != nil {
		return false, nil
	}
	// Set the correct difficulty

	//TODO when add proposal found, rule new signer out because it got undesire 1
	header.Difficulty = CalcDifficulty(snap, signer)
	log.Printf("header.Difficulty=%v", header.Difficulty)
	// Ensure the timestamp has the correct delay
	parent := c.bc.GetHeader(header.PrevHash)
	if parent == nil {
		return false, ErrUnknownAncestor
	}
	header.Time = parent.Time + c.period
	// log.Println("parent.Time=", parent.Time)
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
		log.Println("header.Time set to now.")
	}
	// log.Println("header.Time=", header.Time)

	if header.Difficulty == diffNoTurn {
		delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
		txnutil.Log.Debugf("delay=%v", delay)
		log.Printf("delay=%v", delay)
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		txnutil.Log.Debugf("wiggle=%v", wiggle)
		extraDelay := time.Duration(rand.Int63n(int64(wiggle)))
		delay += extraDelay
		log.Printf("Out-of-turn signing in prepare, extra delay=%v, total delay=%v", extraDelay, strconv.FormatFloat(delay.Seconds(), 'f', 3, 64))
		for {
			select {
			//block arrives at current round, skip wait
			case <-skipCh:
				log.Printf("@@@@@@@@@@@@Prepare skipped! ")
				return false, nil
			//wait out turn delay seconds
			case <-time.After(delay):
				log.Printf("@@@@@@@@@@@@Prepare delay %v done! ", delay)
				return true, nil
			}
		}
	}
	return true, nil
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *PoI) Seal(block *Block, results chan<- *Block, skipCh <-chan struct{}) error {
	header := block.header
	header.PubKey = c.pubKey
	// Bail out if we're unauthorized to sign a block
	snap, err := c.snapshot(header.Number-1, header.PrevHash)
	if err != nil {
		return err
	}
	csigner := SignerFromPubKey(c.pubKey)
	if _, authorized := snap.Signers[csigner]; !authorized {
		return errUnauthorizedSigner
	}

	err = snap.checkRecent(csigner, header.Number)
	if err != nil {
		return err
	}
	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
	// if header.Difficulty == diffNoTurn {
	// 	// It's not our turn explicitly to sign, delay it a bit
	// 	wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
	// 	txnutil.Log.Debugf("wiggle=%v", wiggle)
	// 	extraDelay := time.Duration(rand.Int63n(int64(wiggle)))
	// 	delay += extraDelay
	// 	txnutil.Log.Debugf("Out-of-turn signing requested, extraDelay=%v, total delay=%v", extraDelay, delay)
	// 	log.Printf("Out-of-turn signing requested, extraDelay=%v, total delay=%v", extraDelay, delay)
	// }

	// if delay.Seconds()+float64(c.period) <= 0 { //now mine for a while
	// 	header.Time = uint64(time.Now().Unix())
	// 	delay = 100 * time.Millisecond
	// }
	hashToSign := sigHash(header)
	txnutil.Log.Debugf("hash to sign: %x \n", hashToSign)
	quoted, signature, err := txnutil.PCRSign(txnutil.Hex(hashToSign))
	if err != nil {
		return err
	}
	header.Signature = signature
	header.Quoted = quoted
	log.Printf("block #%d signed by %s...; waiting for %v sec...\n", header.Number, csigner[:3], strconv.FormatFloat(delay.Seconds(), 'f', 3, 64))
	go func() {
		select {
		case <-skipCh:
			txnutil.Log.Debugln("@@@@@@@@@@@@Sealing skipped! ")
			block.Undo()
			return
		case <-time.After(delay):
		}
		select {
		case results <- block.WithSeal(header):
			log.Printf("put into results channel ...#%d", header.Number)
		default:
			log.Println("Error: Sealing result is not read by miner ... ")
			block.Undo()
			return
		}
	}()
	return nil
}

// verifyHeader checks whether hash of the header is the "-q" option of tpm2_quote cmd  signed with.
func (c *PoI) VerifyHeader(header *Header) error {

	hashToVerify := sigHash(header)
	// log.Printf("hash to verify: %x \n", hashToVerify)
	extraData := header.Quoted[44:76]
	if !bytes.Equal(extraData, hashToVerify) {
		return ValidationError("VerifyHeader error: signed block hash is invalid.")
	}
	// log.Printf("quote to verify: %x \n", quoteString)
	log.Printf("block hash correctness: true")
	return c.verifySeal(header)
}

func (c *PoI) verifySeal(header *Header) error {
	number := header.Number
	if number == 0 {
		return ValidationError("errUnknownBlock")
	}
	if err := txnutil.PCRVerify(header.Quoted); err != nil {
		log.Printf("PCRVerify error: %v\n", err)
		return ValidationError("TrustError:", err)
	}
	pubkey, err := txnutil.ParseECPublicKeyFromBlockBytes(header.PubKey)
	if err != nil {
		return err
	}
	if err := txnutil.SignatureVerify(pubkey, header.Signature, header.Quoted); err != nil {
		log.Printf("SignatureVerify error: %v\n", err)
		return ValidationError("TrustError:", err)
	}
	// will not validate with snapshot if it's a catching up
	if diff := uint64(time.Now().Unix()) - header.Time; diff < 20 {
		// Retrieve the snapshot needed to verify this header and cache it
		snap, err := c.snapshot(number-1, header.PrevHash)
		if err != nil {
			return err
		}
		signer, err := SignerFromCert(header.PubKey)
		if err != nil {
			return err
		}
		if _, ok := snap.Signers[signer]; !ok {
			return errUnauthorizedSigner
		}
		err = snap.checkRecent(signer, number)
		if err != nil {
			log.Println("VerifyHeader Error: ", err)
			return err
		}
	}
	return nil
}

func (c *PoI) Finalize(block *Block, txs []*Transaction, receipts []*Receipt) {
	block.SetTransactions(txs)
	block.SetReceipts(receipts)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *PoI) snapshot(number uint64, hash []byte) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(txnutil.Hex(hash)); ok {
			snap = s.(*Snapshot)
			// txnutil.Log.Debugf("[SNAP]Loaded snapshot from cache. number=%d, hash=%x\n, %v\n", number, hash, snap)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%c.checkpointInterval == 0 {
			// txnutil.Log.Debugf("[SNAP]Try to load snapshot from disk. number=%d, hash=%x", number, hash)
			if s, err := loadSnapshot(c.db, hash); err == nil {
				// txnutil.Log.Debugf("[SNAP]Loaded snapshot from disk. number=%d", number)
				snap = s
				break
			}
		}
		if number == 0 {
			genesisHeader := c.bc.GetHeader(hash)
			chash := genesisHeader.Hash()
			signers := make([]string, len(genesisHeader.Signers)/SignerBytesLen)
			for i := 0; i < len(signers); i++ {
				signers[i] = txnutil.Hex(genesisHeader.Signers[i*SignerBytesLen : (i+1)*SignerBytesLen])
			}
			snap = newSnapshot(number, chash, signers)
			if err := snap.store(c.db); err != nil {
				return nil, err
			}
			// txnutil.Log.Debugf("[SNAP]Stored genesis snapshot to disk: number=%d; hash=%x", number, chash)
			break
		}
		// No snapshot for this header, gather the header and move backward
		header := c.bc.GetHeader(hash)
		if header == nil {
			return nil, ErrUnknownAncestor
		}
		headers = append(headers, header)
		number, hash = number-1, header.PrevHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	var err error
	snap, err = snap.apply(headers)
	if err != nil {
		return nil, err
	}
	// in case there are not many peers connected, make sure the add proposal be handled sooner or later

	if snap.Proposal != nil && bytes.Equal(snap.Proposal.Nonce, NonceAuthVote) {
		c.proposal = snap.Proposal
	} else if c.proposal != nil && bytes.Equal(c.proposal.Nonce, NonceAuthVote) {
		snap.Proposal = c.proposal
	}
	h := txnutil.Hex(snap.Hash)
	c.recents.Add(h, snap)
	// txnutil.Log.Debugf("[SNAP]Added snapshot to cache. number=%d, hash=%s\n, %v\n", snap.Number, h, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%c.checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		// txnutil.Log.Debugf("[SNAP]Stored snapshot to disk, number=%d hash=%x", snap.Number, snap.Hash)
	}
	return snap, nil
}
