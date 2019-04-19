package txnchain

import (
	"bytes"
	"encoding/json"
	"log"
	"sort"

	"github.com/truxen-org/chainpoc/txnutil"
)

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []string

func (s signersAscending) Len() int { return len(s) }
func (s signersAscending) Less(i, j int) bool {
	return bytes.Compare(txnutil.FromHex(s[i]), txnutil.FromHex(s[j])) < 0
}
func (s signersAscending) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type Signed struct {
	Last uint64 `json:"last"`
}

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	Number   uint64             `json:"number"`  // Block number where the snapshot was created
	Hash     []byte             `json:"hash"`    // Block hash where the snapshot was created
	Signers  map[string]*Signed `json:"signers"` // Set of authorized signers at this moment, mapping to its last signed block number
	Recents  map[uint64]string  `json:"recents"` // Set of recent signers for spam protections
	Proposal *Proposal          `json:"proposal"`
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.
func newSnapshot(number uint64, hash []byte, signers []string) *Snapshot {
	snap := &Snapshot{
		Number:  number,
		Hash:    hash,
		Signers: make(map[string]*Signed),
		Recents: make(map[uint64]string),
	}
	for _, signer := range signers {
		snap.Signers[signer] = &Signed{0}
	}
	txnutil.Log.Debugln("[SNAP]newSnapshot", snap)
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(db txnutil.Database, hash []byte) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("poi-"), hash[:]...))
	if err != nil {
		log.Printf("[SNAP]Snapshot not found from db: %x", hash)
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	txnutil.Log.Debugln("[SNAP]loadSnapshot", snap)
	return snap, nil
}

func (s *Snapshot) String() string {
	st, _ := json.MarshalIndent(s, "", " ")
	return string(st)
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db txnutil.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	db.Put(append([]byte("poi-"), s.Hash[:]...), blob)
	txnutil.Log.Debugln("[SNAP]store", s)
	return nil
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		Number:  s.Number,
		Hash:    s.Hash,
		Signers: make(map[string]*Signed),
		Recents: make(map[uint64]string),
	}
	for signer, signed := range s.Signers {
		cpy.Signers[signer] = signed
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}

	return cpy
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number != headers[i].Number+1 {
			return nil, errNonContiguousHeaders
		}
	}
	if headers[0].Number != s.Number+1 {
		return nil, errNonContiguousHeaders
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		number := header.Number
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			// txnutil.Log.Debugf("[SNAP]Delete from snapshot.Recents: [%d]%s\n", number-limit, snap.Recents[number-limit])
			delete(snap.Recents, number-limit)
		}
		signer := SignerFromPubKey(header.PubKey)
		if _, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				txnutil.Log.Debugf("[SNAP]recently signed: [%d]%s\n", number, signer)
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = signer
		snap.Signers[signer].Last = number
		// txnutil.Log.Debugf("[SNAP]Add to snapshot.Recents: [%d]%s\n", number, signer)

		if len(header.Extra) != 0 {
			sgr := txnutil.Hex(header.Extra)
			//miner join
			if bytes.Equal(header.Nonce[:], NonceAuthVote) {
				snap.Signers[sgr] = &Signed{number + 1}
				log.Printf("[SNAP]snap.Signers updated: add %s last = %d", sgr, number+1)
			}else if bytes.Equal(header.Nonce[:], NonceDropVote) { //miner remove
				delete(snap.Signers, sgr)
				log.Println("[SNAP]snap.Signers updated: drop", sgr)
			}
			log.Println("[SNAP][proposal]Propose processed when apply snapshot:", snap)
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	// log.Println("[SNAP]applied:", snap)
	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
func (s *Snapshot) signers() []string {
	sigs := make([]string, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(signersAscending(sigs))
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, signer string) bool {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset)
}

func (s *Snapshot) inturnSigner(number uint64) string {
	signers := s.signers()
	offset := number % uint64(len(signers))
	return signers[offset]
}

func (s *Snapshot) checkRecent(signer string, number uint64) error {

	limit := uint64(len(s.Signers)/2 + 1)
	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range s.Recents {
		if recent == signer {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if number < limit || seen > number-limit {
				log.Println("Signed recently")
				return errRecentlySigned
			}
		}
	}
	return nil
}
