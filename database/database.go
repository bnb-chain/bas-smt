package database

type (
	KeyValueReader interface {
		// Has retrieves if a key is present in the key-value data store.
		Has(key []byte) (bool, error)

		// Get retrieves the given key if it's present in the key-value data store.
		Get(key []byte) ([]byte, error)
	}
	KeyValueWriter interface {
		// Set inserts the given value into the key-value data store.
		Set(key []byte, value []byte) error

		// Delete removes the key from the key-value data store.
		Delete(key []byte) error
	}
	TreeDB interface {
		KeyValueReader
		KeyValueWriter
		// NewBatch creates a write-only database that buffers changes to its host db
		// until a final write is called.
		NewBatch() Batcher
		Close() error
	}

	Batcher interface {
		KeyValueWriter

		// Write flushes any accumulated data to disk.
		Write() error

		// Reset resets the batch for reuse.
		Reset()

		// ValueSize retrieves the amount of data queued up for writing.
		ValueSize() int
	}
)
