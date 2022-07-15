package memory

import (
	"sync"

	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/utils"
)

var (
	_ database.TreeDB  = (*MemoryDB)(nil)
	_ database.Batcher = (*batch)(nil)
)

func NewMemoryDB() database.TreeDB {
	return &MemoryDB{
		db: make(map[string][]byte),
	}
}

// MemoryDB is a key-value store.
type MemoryDB struct {
	db   map[string][]byte
	lock sync.RWMutex
}

func (db *MemoryDB) Get(key []byte) ([]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.db == nil {
		return nil, database.ErrDatabaseClosed
	}
	if entry, ok := db.db[string(key)]; ok {
		return utils.CopyBytes(entry), nil
	}
	return nil, database.ErrDatabaseNotFound
}

func (db *MemoryDB) Has(key []byte) (bool, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.db == nil {
		return false, database.ErrDatabaseClosed
	}
	_, ok := db.db[string(key)]
	return ok, nil
}

func (db *MemoryDB) Set(key []byte, value []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	if db.db == nil {
		return database.ErrDatabaseClosed
	}
	db.db[string(key)] = utils.CopyBytes(value)
	return nil
}

func (db *MemoryDB) Delete(key []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	if db.db == nil {
		return database.ErrDatabaseClosed
	}
	delete(db.db, string(key))
	return nil
}

func (db *MemoryDB) NewBatch() database.Batcher {
	return &batch{
		db: db,
	}
}

func (db *MemoryDB) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.db = nil
	return nil
}

// keyvalue is a key-value tuple tagged with a deletion field to allow creating
// memory-database write batches.
type keyvalue struct {
	key    []byte
	value  []byte
	delete bool
}

// batch is a write-only memory batch that commits changes to its host
// database when Write is called. A batch cannot be used concurrently.
type batch struct {
	db     *MemoryDB
	writes []keyvalue
	size   int
}

// Put inserts the given value into the batch for later committing.
func (b *batch) Set(key, value []byte) error {
	b.writes = append(b.writes, keyvalue{utils.CopyBytes(key), utils.CopyBytes(value), false})
	b.size += len(value)
	return nil
}

// Delete inserts the a key removal into the batch for later committing.
func (b *batch) Delete(key []byte) error {
	b.writes = append(b.writes, keyvalue{utils.CopyBytes(key), nil, true})
	b.size += len(key)
	return nil
}

// Write flushes any accumulated data to the memory database.
func (b *batch) Write() error {
	b.db.lock.Lock()
	defer b.db.lock.Unlock()

	for _, keyvalue := range b.writes {
		if keyvalue.delete {
			delete(b.db.db, string(keyvalue.key))
			continue
		}
		b.db.db[string(keyvalue.key)] = keyvalue.value
	}
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *batch) ValueSize() int {
	return b.size
}

// Reset resets the batch for reuse.
func (b *batch) Reset() {
	b.writes = b.writes[:0]
	b.size = 0
}
