package bsmt

import (
	"bytes"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/database/memory"
	"github.com/bnb-chain/bas-smt/utils"
)

var (
	latestVersionKey          = []byte(`latestVersion`)
	recentVersionNumberKey    = []byte(`recentVersionNumber`)
	storaegFullTreeNodePrefix = []byte(`t`)
	sep                       = []byte(`:`)
)

func storageFullTreeNodeKey(depth uint8, path uint64) []byte {
	depthBuf := make([]byte, 8)
	pathBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(depthBuf, uint64(depth))
	binary.BigEndian.PutUint64(pathBuf, path)
	return bytes.Join([][]byte{storaegFullTreeNodePrefix, depthBuf, pathBuf}, sep)
}

var _ SparseMerkleTree = (*BASSparseMerkleTree)(nil)

func NewBASSparseMerkleTree(hasher *Hasher, db database.TreeDB, maxVersionNum, maxDepth uint64, nilHash []byte,
	opts ...Option) (SparseMerkleTree, error) {
	smt := &BASSparseMerkleTree{
		maxDepth:      maxDepth,
		maxVersionNum: maxVersionNum,
		journal:       map[journalKey]*TreeNode{},
		nilHashes:     constuctNilHashes(maxDepth, nilHash, hasher),
		hasher:        hasher,
	}

	for _, opt := range opts {
		opt(smt)
	}

	if db == nil {
		db = memory.NewMemoryDB()
	}

	recoveryTree(smt, db)
	smt.db = db
	return smt, nil
}

func constuctNilHashes(maxDepth uint64, nilHash []byte, hasher *Hasher) map[uint8][]byte {
	if maxDepth == 0 {
		return map[uint8][]byte{0: nilHash}
	}
	nilHashes := make(map[uint8][]byte, maxDepth)
	nilHashes[0] = nilHash
	for i := 0; i < int(maxDepth); i++ {
		nilHash = hasher.Hash(nilHash, nilHash)
		nilHashes[uint8(i)] = nilHash
	}

	return nilHashes
}

func recoveryTree(smt *BASSparseMerkleTree, db database.TreeDB) {
	// init
	smt.root = NewTreeNode(0, 0, smt.nilHashes, smt.hasher)

	// recovery version info
	buf, err := db.Get(latestVersionKey)
	if err != nil {
		return
	}
	smt.version = Version(binary.BigEndian.Uint64(buf))
	buf, err = db.Get(recentVersionNumberKey)
	if err != nil {
		return
	}
	smt.recentVersion = Version(binary.BigEndian.Uint64(buf))

	// recovery root node from stroage
	rlpBytes, err := db.Get(storageFullTreeNodeKey(0, 0))
	if err != nil {
		return
	}
	storageTreeNode := &StorageTreeNode{}
	err = rlp.DecodeBytes(rlpBytes, storageTreeNode)
	if err != nil {
		return
	}
	smt.root = storageTreeNode.ToTreeNode(0, 0, smt.nilHashes, smt.hasher)
}

type journalKey struct {
	depth uint8
	path  uint64
}

type BASSparseMerkleTree struct {
	version       Version
	recentVersion Version
	root          *TreeNode
	lastSaveRoot  *TreeNode
	journal       map[journalKey]*TreeNode
	maxDepth      uint64
	maxVersionNum uint64
	nilHashes     map[uint8][]byte
	hasher        *Hasher
	db            database.TreeDB
}

func (tree *BASSparseMerkleTree) Get(key uint64, version *Version) ([]byte, error) {
	if tree.IsEmpty() {
		return nil, ErrEmptyRoot
	}

	if version == nil {
		version = &tree.version
	}

	if tree.recentVersion > *version {
		return nil, ErrVersionTooOld
	}

	if *version > tree.version {
		return nil, ErrVersionTooHigh
	}

	targetNode := tree.root
	var depth uint8 = 0
	for i := 0; i < int(tree.maxDepth)/4; i++ {
		nibbleKey := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := nibbleKey & 0x0000000f
		if targetNode.Children[nibble] == nil {
			tree.constructNode(targetNode, nibble, nibbleKey, depth)
		}
		targetNode = targetNode.Children[nibble]

		depth += 4
	}

	return targetNode.Root(), nil
}

func (tree *BASSparseMerkleTree) constructNode(node *TreeNode, nibble, path uint64, depth uint8) {
	for i := uint64(0); i < 16; i++ {
		treeNode := NewTreeNode(depth, path-nibble+i, tree.nilHashes, tree.hasher)
		rlpBytes, _ := tree.db.Get(storageFullTreeNodeKey(depth, path-nibble+i))
		if rlpBytes != nil {
			stroageTreeNode := &StorageTreeNode{}
			if rlp.DecodeBytes(rlpBytes, stroageTreeNode) == nil {
				node.Children[i] = stroageTreeNode.ToTreeNode(
					depth, path-nibble+i, tree.nilHashes, tree.hasher)
			}
			continue
		}

		node.Children[i] = treeNode
	}
}

func (tree *BASSparseMerkleTree) Set(key uint64, val []byte) {
	newVersion := tree.version + 1

	targetNode := tree.root
	var depth uint8 = 0
	var parentNodes []*TreeNode
	for i := 0; i < int(tree.maxDepth)/4; i++ {
		nibbleKey := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := nibbleKey & 0x0000000f
		parentNodes = append(parentNodes, targetNode)
		if targetNode.Children[nibble] == nil {
			tree.constructNode(targetNode, nibble, nibbleKey, depth)
		}
		targetNode = targetNode.Children[nibble]

		depth += 4
	}
	targetNode = targetNode.Set(val, newVersion)
	tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	// recompute root hash
	for i := len(parentNodes) - 1; i >= 0; i-- {
		nibble := key >> (int(tree.maxDepth) - (i+1)*4) & 0x0000000f
		targetNode = parentNodes[i].SetChildren(targetNode, int(nibble))
		targetNode.ComputeInternalHash(newVersion)
		tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	}
	tree.root = targetNode
}

func (tree *BASSparseMerkleTree) IsEmpty() bool {
	return bytes.Equal(tree.root.Root(), tree.nilHashes[0])
}

func (tree *BASSparseMerkleTree) Root() []byte {
	return tree.root.Root()
}

func (tree *BASSparseMerkleTree) GetProof(key uint64, version *Version) (*Proof, error) {
	if tree.IsEmpty() {
		return nil, ErrEmptyRoot
	}

	if version == nil {
		version = &tree.version
	}

	if tree.recentVersion > *version {
		return nil, ErrVersionTooOld
	}

	if *version > tree.version {
		return nil, ErrVersionTooHigh
	}

	targetNode := tree.root
	var depth uint8 = 0
	var proofs [][]byte
	var helpers []int

	for i := 0; i < int(tree.maxDepth)/4; i++ {
		nibbleKey := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := nibbleKey & 0x0000000f
		if targetNode.Children[nibble] == nil {
			tree.constructNode(targetNode, nibble, nibbleKey, depth)
		}
		proofs = append(proofs, targetNode.Root())
		helpers = append(helpers, int(nibble)/16%2)
		index := 0
		for j := 0; j < 3; j++ {
			// nibble / 8
			// nibble / 4
			// nibble / 2
			inc := int(nibble) / (1 << (3 - j))
			proofs = append(proofs, targetNode.Internals[index+inc])
			helpers = append(helpers, inc%2)
			index += 1 << (j + 1)
		}

		targetNode = targetNode.Children[nibble]
		depth += 4
	}
	proofs = append(proofs, targetNode.Root())
	helpers = append(helpers, int(key)%2)

	return &Proof{
		MerkleProof: proofs,
		ProofHelper: helpers[1:],
	}, nil
}

func (tree *BASSparseMerkleTree) VerifyProof(proof *Proof, version *Version) bool {
	if tree.IsEmpty() {
		return false
	}

	if version == nil {
		version = &tree.version
	}

	if tree.recentVersion > *version {
		return false
	}

	if *version > tree.version {
		return false
	}

	targetNode := tree.root
	var depth uint8 = 0
	for i := 0; i < len(proof.ProofHelper); i += 4 {
		if !bytes.Equal(targetNode.Root(), proof.MerkleProof[i]) {
			return false
		}

		index := proof.ProofHelper[i]
		for j := 1; j < 3; j++ {
			if !bytes.Equal(targetNode.Internals[index], proof.MerkleProof[i+j]) {
				return false
			}
			index = index*2 + 2 + proof.ProofHelper[i+j]
		}
		index = index*2 + 4 - 16
		if targetNode.Children[index] == nil {
			tree.constructNode(targetNode, uint64(index), utils.BinaryToDecimal(proof.ProofHelper[:i]), depth)
		}
		targetNode = targetNode.Children[index]
		depth += 4
	}

	return true
}

func (tree *BASSparseMerkleTree) LatestVersion() Version {
	return tree.version
}

func (tree *BASSparseMerkleTree) Reset() {
	tree.journal = make(map[journalKey]*TreeNode)
	tree.root = tree.lastSaveRoot
}

func (tree *BASSparseMerkleTree) writeNode(db database.Batcher, fullNode *TreeNode, version Version) error {
	// prune
	fullNode.Prune(tree.recentVersion)

	// persist tree
	rlpBytes, err := rlp.EncodeToBytes(fullNode.ToStorageTreeNode())
	if err != nil {
		return err
	}
	err = db.Set(storageFullTreeNodeKey(fullNode.depth, fullNode.path), rlpBytes)
	if err != nil {
		return err
	}
	return nil
}

func (tree *BASSparseMerkleTree) Commit() (Version, error) {
	newVersion := tree.version + 1

	if tree.db != nil {
		// write tree nodes, prune old version
		batch := tree.db.NewBatch()
		for _, node := range tree.journal {
			err := tree.writeNode(batch, node, newVersion)
			if err != nil {
				return tree.version, err
			}
		}
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newVersion))
		err := batch.Set(latestVersionKey, buf)
		if err != nil {
			return tree.version, err
		}

		if uint64(newVersion) > tree.maxVersionNum {
			tree.recentVersion++
		}
		buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(tree.recentVersion))
		err = batch.Set(recentVersionNumberKey, buf)
		if err != nil {
			return tree.version, err
		}

		err = batch.Write()
		if err != nil {
			return tree.version, err
		}
	}

	tree.version = newVersion
	tree.journal = make(map[journalKey]*TreeNode)
	tree.lastSaveRoot = tree.root
	return newVersion, nil
}

func (tree *BASSparseMerkleTree) rollback(child *TreeNode, oldVersion Version, db database.Batcher) error {
	if child == nil {
		return nil
	}
	// remove value nodes
	next := child.Rollback(oldVersion)
	if !next {
		return nil
	}

	child.ComputeInternalHash(oldVersion)

	// persist tree
	rlpBytes, err := rlp.EncodeToBytes(child.ToStorageTreeNode())
	if err != nil {
		return err
	}
	err = db.Set(storageFullTreeNodeKey(child.depth, child.path), rlpBytes)
	if err != nil {
		return err
	}

	for _, subChild := range child.Children {
		err := tree.rollback(subChild, oldVersion, db)
		if err != nil {
			return err
		}
	}

	return nil
}

func (tree *BASSparseMerkleTree) Rollback(version Version) error {
	if tree.IsEmpty() {
		return ErrEmptyRoot
	}

	if tree.recentVersion > version {
		return ErrVersionTooOld
	}

	if version > tree.version {
		return ErrVersionTooHigh
	}

	tree.Reset()

	newVersion := version
	newRecentVersion := uint64(0)
	if uint64(version) > tree.maxVersionNum {
		newRecentVersion = uint64(version) - tree.maxVersionNum
	}
	if tree.db != nil {
		batch := tree.db.NewBatch()
		tree.rollback(tree.root, version, batch)

		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newVersion))
		err := batch.Set(latestVersionKey, buf)
		if err != nil {
			return err
		}

		buf = make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newRecentVersion))
		err = batch.Set(recentVersionNumberKey, buf)
		if err != nil {
			return err
		}

		err = batch.Write()
		if err != nil {
			return err
		}
	}

	tree.version = newVersion
	tree.recentVersion = Version(newRecentVersion)
	return nil
}
