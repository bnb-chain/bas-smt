package redis

import (
	"bytes"
	"context"
	stdErrors "errors"

	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/utils"
	"github.com/go-redis/redis/v8"
)

var (
	_ database.TreeDB  = (*Database)(nil)
	_ database.Batcher = (*batch)(nil)
)

// New returns a wrapped Redis object.
func New(config *RedisConfig, opts ...Option) (*Database, error) {
	var client RedisClient
	if len(config.ClusterAddr) > 0 {
		// cluster mode
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:              config.ClusterAddr,
			PoolSize:           config.PoolSize,
			Username:           config.Username,
			Password:           config.Password,
			MaxRedirects:       config.MaxRedirects,
			ReadOnly:           config.ReadOnly,
			RouteByLatency:     config.RouteByLatency,
			RouteRandomly:      config.RouteRandomly,
			MaxRetries:         config.MaxRetries,
			MinRetryBackoff:    config.MinRetryBackoff,
			MaxRetryBackoff:    config.MaxRetryBackoff,
			DialTimeout:        config.DialTimeout,
			ReadTimeout:        config.ReadTimeout,
			WriteTimeout:       config.WriteTimeout,
			MinIdleConns:       config.MinIdleConns,
			MaxConnAge:         config.MaxConnAge,
			PoolFIFO:           config.PoolFIFO,
			PoolTimeout:        config.PoolTimeout,
			IdleTimeout:        config.IdleTimeout,
			IdleCheckFrequency: config.IdleCheckFrequency,
		})
	} else {
		// single node mode
		client = redis.NewClient(&redis.Options{
			Addr:               config.Addr,
			PoolSize:           config.PoolSize,
			Username:           config.Username,
			Password:           config.Password,
			MaxRetries:         config.MaxRetries,
			MinRetryBackoff:    config.MinRetryBackoff,
			MaxRetryBackoff:    config.MaxRetryBackoff,
			DialTimeout:        config.DialTimeout,
			ReadTimeout:        config.ReadTimeout,
			WriteTimeout:       config.WriteTimeout,
			MinIdleConns:       config.MinIdleConns,
			MaxConnAge:         config.MaxConnAge,
			PoolFIFO:           config.PoolFIFO,
			PoolTimeout:        config.PoolTimeout,
			IdleTimeout:        config.IdleTimeout,
			IdleCheckFrequency: config.IdleCheckFrequency,
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.DialTimeout)
	defer cancel()
	err := client.Ping(ctx).Err()
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		opt.Apply(client)
	}

	return &Database{
		db: client,
	}, nil
}

// NewFromExistRedisClient returns a wrapped Redis object.
func NewFromExistRedisClient(db RedisClient) *Database {
	return &Database{
		db: db,
	}
}

// WrapWithNamespace returns a wrapped Redis object.
// The namespace is the prefix that the datastore.
func WrapWithNamespace(db *Database, namespace string) *Database {
	db.namespace = []byte(namespace)
	return db
}

type Database struct {
	namespace []byte
	db        RedisClient // redis client
}

// wrapKey returns a wrapper key with namespace.
func wrapKey(namespace, key []byte) string {
	if len(namespace) > 0 {
		return utils.BytesToString((bytes.Join([][]byte{namespace, key}, []byte(":"))))
	}
	return utils.BytesToString(key)
}

// Close flushes any pending data to disk and closes
// all io accesses to the underlying key-value store.
func (db *Database) Close() error {
	return db.db.Close()
}

// Has retrieves if a key is present in the key-value store.
func (db *Database) Has(key []byte) (bool, error) {
	dat, err := db.db.Exists(context.Background(), wrapKey(db.namespace, key)).Result()
	if err != nil {
		return false, err
	}
	return dat > 0, nil
}

// Get retrieves the given key if it's present in the key-value store.
func (db *Database) Get(key []byte) ([]byte, error) {
	dat, err := db.db.Get(context.Background(), wrapKey(db.namespace, key)).Result()
	if err != nil && stdErrors.Is(redis.Nil, err) {
		return nil, database.ErrDatabaseNotFound
	}
	return utils.StringToBytes(dat), err
}

// Put inserts the given value into the key-value store.
func (db *Database) Set(key []byte, value []byte) error {
	return db.db.Set(context.Background(), wrapKey(db.namespace, key), value, 0).Err()
}

// Delete removes the key from the key-value store.
func (db *Database) Delete(key []byte) error {
	return db.db.Del(context.Background(), wrapKey(db.namespace, key)).Err()
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
func (db *Database) NewBatch() database.Batcher {
	return &batch{
		db:        db.db,
		namespace: db.namespace,
		b:         db.db.Pipeline(),
	}
}

// batch is a write-only leveldb batch that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
type batch struct {
	namespace []byte
	db        RedisClient
	b         redis.Pipeliner
	size      int
}

// Put inserts the given value into the batch for later committing.
func (b *batch) Set(key, value []byte) error {
	b.b.Set(context.Background(), wrapKey(b.namespace, key), value, 0)
	b.size += len(value)
	return nil
}

// Delete inserts the a key removal into the batch for later committing.
func (b *batch) Delete(key []byte) error {
	b.b.Del(context.Background(), wrapKey(b.namespace, key))
	b.size += len(key)
	return nil
}

// Write flushes any accumulated data to disk.
func (b *batch) Write() error {
	_, err := b.b.Exec(context.Background())
	if err != nil {
		return err
	}
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
func (b *batch) ValueSize() int {
	return b.size
}

// Reset resets the batch for reuse.
func (b *batch) Reset() {
	b.b = b.db.Pipeline()
	b.size = 0
}
