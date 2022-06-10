package bsmt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/bnb-chain/bas-smt/accumulators/merkleTree"
	"github.com/bnb-chain/bas-smt/database"
	wrappedLevelDB "github.com/bnb-chain/bas-smt/database/leveldb"
	"github.com/bnb-chain/bas-smt/database/memory"

	"github.com/ethereum/go-ethereum/common"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/storage"
)

var (
	nilHash = common.FromHex("01ef55cdf3b9b0d65e6fb6317f79627534d971fd96c811281af618c0028d5e7a")
)

type testEnv struct {
	hasher *Hasher
	db     database.TreeDB
}

func prepareEnv(t *testing.T) []testEnv {
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		t.Fatal(err)
	}

	return []testEnv{
		{
			hasher: &Hasher{sha256.New()},
			db:     memory.NewMemoryDB(),
		},
		{
			hasher: &Hasher{sha256.New()},
			db:     wrappedLevelDB.WrapWithNamespace(wrappedLevelDB.NewFromExistLevelDB(db), "test"),
		},
	}
}

func testProof(t *testing.T, hasher *Hasher, db database.TreeDB) {
	smt, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}

	key1 := uint64(0)
	key2 := uint64(255)
	key3 := uint64(213)
	val1 := hasher.Hash([]byte("test1"))
	version := smt.LatestVersion()
	_, err = smt.Get(key1, &version)
	if err == nil {
		t.Fatal("tree contains element before write")
	} else if !errors.Is(err, ErrEmptyRoot) {
		t.Fatal(err)
	}

	val2 := hasher.Hash([]byte("test2"))
	val3 := hasher.Hash([]byte("test3"))
	smt.Set(key1, val1)
	smt.Set(key2, val2)
	smt.Set(key3, val3)

	version, err = smt.Commit()
	if err != nil {
		t.Fatal(err)
	}

	hash1, err := smt.Get(key1, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash1, val1) {
		t.Fatalf("not equal to the original, want: %v, got: %v", val1, hash1)
	}

	hash2, err := smt.Get(key2, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash2, val2) {
		t.Fatalf("not equal to the original, want: %v, got: %v", val2, hash2)
	}

	hash3, err := smt.Get(key3, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash3, val3) {
		t.Fatalf("not equal to the original, want: %v, got: %v", val3, hash3)
	}

	proof, err := smt.GetProof(key1, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof1 failed")
	}

	proof, err = smt.GetProof(key2, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof2 failed")
	}

	proof, err = smt.GetProof(key3, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof3 failed")
	}

	// restore tree from db
	smt2, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}

	hash11, err := smt2.Get(key1, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash1, hash11) {
		t.Fatalf("not equal to the original, want: %v, got: %v", hash1, hash11)
	}

	hash22, err := smt2.Get(key2, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash2, hash22) {
		t.Fatalf("not equal to the original, want: %v, got: %v", hash2, hash22)
	}

	hash33, err := smt2.Get(key3, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hash3, hash33) {
		t.Fatalf("not equal to the original, want: %v, got: %v", hash3, hash33)
	}

	proof, err = smt2.GetProof(key1, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof1 failed")
	}

	proof, err = smt2.GetProof(key2, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof2 failed")
	}

	proof, err = smt2.GetProof(key3, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt.VerifyProof(proof, &version) {
		t.Fatal("verify proof2 failed")
	}
}

func Test_BASSparseMerkleTree_Proof(t *testing.T) {
	for _, env := range prepareEnv(t) {
		testProof(t, env.hasher, env.db)
		env.db.Close()
	}
}

func testRollback(t *testing.T, hasher *Hasher, db database.TreeDB) {
	smt, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}

	key1 := uint64(1)
	key2 := uint64(2)
	key3 := uint64(23)
	val1 := hasher.Hash([]byte("test1"))
	val2 := hasher.Hash([]byte("test2"))
	val3 := hasher.Hash([]byte("test3"))
	smt.Set(key1, val1)
	smt.Set(key2, val2)

	version1, err := smt.Commit()
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key1, &version1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key2, &version1)
	if err != nil {
		t.Fatal(err)
	}

	smt.Set(key3, val3)
	version2, err := smt.Commit()
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key3, &version2)
	if err != nil {
		t.Fatal(err)
	}

	err = smt.Rollback(version1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key3, &version2)
	if !errors.Is(err, ErrVersionTooHigh) {
		t.Fatal(err)
	}

	_, err = smt.GetProof(key3, &version2)
	if !errors.Is(err, ErrVersionTooHigh) {
		t.Fatal(err)
	}

	// restore tree from db
	smt2, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = smt2.Get(key3, &version2)
	if !errors.Is(err, ErrVersionTooHigh) {
		t.Fatal(err)
	}

	_, err = smt2.GetProof(key3, &version2)
	if !errors.Is(err, ErrVersionTooHigh) {
		t.Fatal(err)
	}
}

func Test_BASSparseMerkleTree_Rollback(t *testing.T) {
	for _, env := range prepareEnv(t) {
		testRollback(t, env.hasher, env.db)
		env.db.Close()
	}
}

func testReset(t *testing.T, hasher *Hasher, db database.TreeDB) {
	smt, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}

	key1 := uint64(1)
	key2 := uint64(2)
	key3 := uint64(3)
	val1 := hasher.Hash([]byte("test1"))
	val2 := hasher.Hash([]byte("test2"))
	val3 := hasher.Hash([]byte("test3"))
	smt.Set(key1, val1)
	smt.Set(key2, val2)

	version1, err := smt.Commit()
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key1, &version1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key2, &version1)
	if err != nil {
		t.Fatal(err)
	}

	smt.Set(key3, val3)
	smt.Reset()
}

func Test_BASSparseMerkleTree_Reset(t *testing.T) {
	for _, env := range prepareEnv(t) {
		testReset(t, env.hasher, env.db)
		env.db.Close()
	}
}

func testZecrey(t *testing.T, hasher *Hasher, db database.TreeDB) {
	hashState := merkleTree.MockState(6)
	leaves := merkleTree.CreateLeaves(hashState)
	tree, err := merkleTree.NewTree(leaves, 8, nilHash, hasher.hasher)
	if err != nil {
		t.Fatal(err)
	}

	// verify index belongs to len(t.leaves)
	merkleProofs, helperMerkleProofs, err := tree.BuildMerkleProofs(4)
	if err != nil {
		t.Fatal(err)
	}

	bsmt, err := NewBASSparseMerkleTree(hasher, db, 50, 8, nilHash)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(hashState); i++ {
		err = bsmt.Set(uint64(i), hashState[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	version, err := bsmt.Commit()
	if err != nil {
		t.Fatal(err)
	}

	bsmtProof, err := bsmt.GetProof(4, &version)
	if err != nil {
		t.Fatal(err)
	}
	if !bsmt.VerifyProof(bsmtProof, &version) {
		t.Fatal("bsmt verify proof faild")
	}

	tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)

}

func Test_Zecrey(t *testing.T) {
	for _, env := range prepareEnv(t) {
		testZecrey(t, env.hasher, env.db)
		env.db.Close()
	}
}
