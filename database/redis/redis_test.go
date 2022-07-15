package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/database/dbtest"
	"github.com/go-redis/redis/v8"
)

func TestRedis(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() database.TreeDB {
			mr, err := miniredis.Run()
			if err != nil {
				t.Fatal(err)
			}
			client := redis.NewClient(&redis.Options{
				Addr: mr.Addr(),
			})
			return &Database{
				db: client,
			}
		})
	})
}

func TestRedisWithNamespace(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() database.TreeDB {
			mr, err := miniredis.Run()
			if err != nil {
				t.Fatal(err)
			}
			client := redis.NewClient(&redis.Options{
				Addr: mr.Addr(),
			})

			return WrapWithNamespace(&Database{
				db: client,
			}, "test")
		})
	})
}
