package bsmt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bnb-chain/bas-smt/accumulators/merkleTree"
	"github.com/bnb-chain/bas-smt/database"
	wrappedLevelDB "github.com/bnb-chain/bas-smt/database/leveldb"
	"github.com/bnb-chain/bas-smt/database/memory"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/stretchr/testify/assert"

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
	key2 := uint64(1)
	key3 := uint64(2)
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

	_, err = smt.Get(key1, &version)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key2, &version)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt.Get(key3, &version)
	if err != nil {
		t.Fatal(err)
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

	_, err = smt2.Get(key1, &version)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt2.Get(key2, &version)
	if err != nil {
		t.Fatal(err)
	}

	_, err = smt2.Get(key3, &version)
	if err != nil {
		t.Fatal(err)
	}

	proof, err = smt2.GetProof(key1, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt2.VerifyProof(proof, &version) {
		t.Fatal("verify proof1 failed")
	}

	proof, err = smt2.GetProof(key2, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt2.VerifyProof(proof, &version) {
		t.Fatal("verify proof2 failed")
	}

	proof, err = smt2.GetProof(key3, &version)
	if err != nil {
		t.Fatal(err)
	}

	if !smt2.VerifyProof(proof, &version) {
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
	elapse := time.Now()
	hashState := merkleTree.MockState(6)
	fmt.Println(time.Since(elapse))
	leaves := merkleTree.CreateLeaves(hashState)
	elapse = time.Now()
	h := mimc.NewMiMC()
	nilHash := h.Sum([]byte{})
	fmt.Println("nil hash:", common.Bytes2Hex(nilHash))
	h.Reset()
	tree, err := merkleTree.NewTree(leaves, 5, nilHash, h)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("BuildTree tree time:", time.Since(elapse))
	fmt.Println("height:", tree.MaxHeight)
	fmt.Println("root:", merkleTree.ToString(tree.RootNode.Value))
	fmt.Println("nil root:", merkleTree.ToString(tree.NilHashValueConst[0]))
	elapse = time.Now()
	// verify index belongs to len(t.leaves)
	merkleProofs, helperMerkleProofs, err := tree.BuildMerkleProofs(4)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("len:", len(merkleProofs))
	fmt.Println("BuildTree proofs time:", time.Since(elapse))
	fmt.Println("merkle proof helper:", helperMerkleProofs)
	res := tree.VerifyMerkleProofs(merkleProofs, helperMerkleProofs)
	assert.Equal(t, res, true, "BuildTree merkle proofs successfully")

}

func Test_Zecrey(t *testing.T) {
	for _, env := range prepareEnv(t) {
		testZecrey(t, env.hasher, env.db)
		env.db.Close()
	}
}
