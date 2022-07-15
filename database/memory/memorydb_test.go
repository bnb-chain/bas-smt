package memory

import (
	"testing"

	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/database/dbtest"
)

func TestMemoryDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() database.TreeDB {
			return NewMemoryDB()
		})
	})
}
