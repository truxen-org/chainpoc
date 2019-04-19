package txndb

import (
	"fmt"
	"log"
	"path"

	"github.com/truxen-org/chainpoc/txnutil"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type LDBDatabase struct {
	db *leveldb.DB
}

var DB txnutil.Database

func InitDB() {
	dbPath := path.Join(txnutil.Config.BaseDir, ".chainpoc", "database")
	db, err := NewLDBDatabase(dbPath)
	if err != nil {
		log.Fatal(err.Error())
	}
	DB = db
}

func NewLDBDatabase(dbPath string) (*LDBDatabase, error) {
	// db, err := leveldb.OpenFile(dbPath, nil)

	cache := txnutil.Config.DBCache
	// // Open the db
	db, err := leveldb.OpenFile(dbPath, &opt.Options{
		// 	OpenFilesCacheCapacity: cache,
		BlockCacheCapacity: cache * opt.MiB,
		// Compression:        opt.NoCompression,
		WriteBuffer: cache * opt.MiB, // Two of these are used internally
		// 	Filter:                 filter.NewBloomFilter(10),
	})
	if err != nil {
		return nil, err
	}

	database := &LDBDatabase{db: db}

	return database, nil
}

func (db *LDBDatabase) Put(key []byte, value []byte) {
	err := db.db.Put(key, value, nil)
	if err != nil {
		fmt.Println("Error put", err)
	}
}

func (db *LDBDatabase) Get(key []byte) ([]byte, error) {
	return db.db.Get(key, nil)
}

func (db *LDBDatabase) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

func (db *LDBDatabase) Db() *leveldb.DB {
	return db.db
}

func (db *LDBDatabase) LastKnownTD() []byte {
	data, _ := db.db.Get([]byte("LastKnownTotalDifficulty"), nil)

	if len(data) == 0 {
		data = []byte{0x0}
	}

	return data
}

func (db *LDBDatabase) GetKeys() []*txnutil.Key {
	data, _ := db.Get([]byte("KeyRing"))

	return []*txnutil.Key{txnutil.NewKeyFromBytes(data)}
}

func (db *LDBDatabase) Close() {
	// Close the leveldb database
	db.db.Close()
}

func (db *LDBDatabase) Print() {
	iter := db.db.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		fmt.Printf("%x(%d): ", key, len(key))
		node := txnutil.NewValueFromBytes(value)
		fmt.Printf("%v\n\n", node)
	}
}
