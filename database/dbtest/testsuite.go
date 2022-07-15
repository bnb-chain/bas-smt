package dbtest

import (
	"bytes"
	"testing"

	"github.com/bnb-chain/bas-smt/database"
)

// TestDatabaseSuite runs a suite of tests against a KeyValueStore database
// implementation.
func TestDatabaseSuite(t *testing.T, New func() database.TreeDB) {
	t.Run("KeyValueOperations", func(t *testing.T) {
		db := New()
		defer db.Close()

		key := []byte("foo")

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if got {
			t.Errorf("wrong value: %t", got)
		}

		value := []byte("hello world")
		if err := db.Set(key, value); err != nil {
			t.Error(err)
		}

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if !got {
			t.Errorf("wrong value: %t", got)
		}

		if got, err := db.Get(key); err != nil {
			t.Error(err)
		} else if !bytes.Equal(got, value) {
			t.Errorf("wrong value: %q", got)
		}

		if err := db.Delete(key); err != nil {
			t.Error(err)
		}

		if got, err := db.Has(key); err != nil {
			t.Error(err)
		} else if got {
			t.Errorf("wrong value: %t", got)
		}
	})

	t.Run("Batch", func(t *testing.T) {
		db := New()
		defer db.Close()

		b := db.NewBatch()
		for _, k := range []string{"1", "2", "3", "4"} {
			if err := b.Set([]byte(k), nil); err != nil {
				t.Fatal(err)
			}
		}

		if has, err := db.Has([]byte("1")); err != nil {
			t.Fatal(err)
		} else if has {
			t.Error("db contains element before batch write")
		}

		if err := b.Write(); err != nil {
			t.Fatal(err)
		}

		b.Reset()

		// Mix writes and deletes in batch
		b.Set([]byte("5"), nil)
		b.Delete([]byte("1"))
		b.Set([]byte("6"), nil)
		b.Delete([]byte("3"))
		b.Set([]byte("3"), []byte("test3"))

		if err := b.Write(); err != nil {
			t.Fatal(err)
		}
		type obj struct {
			Key   []byte
			Val   []byte
			Exist bool
		}
		testObjs := []obj{
			{
				Key:   []byte("1"),
				Exist: false,
			},
			{
				Key:   []byte("2"),
				Val:   nil,
				Exist: true,
			},
			{
				Key:   []byte("3"),
				Val:   []byte("test3"),
				Exist: true,
			},
			{
				Key:   []byte("4"),
				Val:   nil,
				Exist: true,
			},
			{
				Key:   []byte("5"),
				Val:   nil,
				Exist: true,
			},
			{
				Key:   []byte("6"),
				Val:   nil,
				Exist: true,
			},
		}
		{
			for _, testObj := range testObjs {
				if testObj.Exist {
					if got, err := db.Get(testObj.Key); err != nil {
						t.Error(err)
					} else if !bytes.Equal(got, testObj.Val) {
						t.Errorf("wrong value: %q", got)
					}
				} else {
					if got, err := db.Has(testObj.Key); err != nil {
						t.Error(err)
					} else if got {
						t.Errorf("wrong value: %t", got)
					}
				}
			}
		}
	})
}
