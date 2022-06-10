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
	pathBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(pathBuf, path)
	return bytes.Join([][]byte{storaegFullTreeNodePrefix, {depth}, pathBuf}, sep)
}

var _ SparseMerkleTree = (*BASSparseMerkleTree)(nil)

func NewBASSparseMerkleTree(hasher *Hasher, db database.TreeDB, maxVersionNum uint64, maxDepth uint8, nilHash []byte,
	opts ...Option) (SparseMerkleTree, error) {

	if maxDepth%4 != 0 {
		return nil, ErrInvalidDepth
	}

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

func constuctNilHashes(maxDepth uint8, nilHash []byte, hasher *Hasher) map[uint8][]byte {
	if maxDepth == 0 {
		return map[uint8][]byte{0: nilHash}
	}
	nilHashes := make(map[uint8][]byte, maxDepth)
	nilHashes[0] = nilHash
	for i := 0; i <= int(maxDepth); i++ {
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
	maxDepth      uint8
	maxVersionNum uint64
	nilHashes     map[uint8][]byte
	hasher        *Hasher
	db            database.TreeDB
}

func (tree *BASSparseMerkleTree) extendNode(node *TreeNode, nibble, path uint64, depth uint8) {
	if node.Children[nibble] == nil {
		node.Children[nibble] = NewTreeNode(depth, path, tree.nilHashes, tree.hasher)
	}
	if !node.Children[nibble].Extended() {
		tree.constructNode(node, nibble, path, depth)
	}

}

func (tree *BASSparseMerkleTree) constructNode(node *TreeNode, nibble, path uint64, depth uint8) {
	rlpBytes, _ := tree.db.Get(storageFullTreeNodeKey(depth, path))
	if rlpBytes != nil {
		stroageTreeNode := &StorageTreeNode{}
		if rlp.DecodeBytes(rlpBytes, stroageTreeNode) == nil {
			node.Children[nibble] = stroageTreeNode.ToTreeNode(
				depth, path, tree.nilHashes, tree.hasher)
			return
		}
	}
	node.Children[nibble] = NewTreeNode(depth, path, tree.nilHashes, tree.hasher)
}

func (tree *BASSparseMerkleTree) Get(key uint64, version *Version) ([]byte, error) {
	if tree.IsEmpty() {
		return nil, ErrEmptyRoot
	}

	if key >= 1<<tree.maxDepth {
		return nil, ErrInvalidKey
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
	var depth uint8 = 4
	for i := 0; i < int(tree.maxDepth)/4; i++ {
		path := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := path & 0x0000000f
		tree.extendNode(targetNode, nibble, path, depth)
		targetNode = targetNode.Children[nibble]

		depth += 4
	}

	return targetNode.Root(), nil
}

func (tree *BASSparseMerkleTree) Set(key uint64, val []byte) error {
	if key >= 1<<tree.maxDepth {
		return ErrInvalidKey
	}
	newVersion := tree.version + 1

	targetNode := tree.root
	var depth uint8 = 4
	var parentNodes []*TreeNode
	for i := 0; i < int(tree.maxDepth)/4; i++ {
		path := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := path & 0x0000000f
		parentNodes = append(parentNodes, targetNode)
		tree.extendNode(targetNode, nibble, path, depth)
		targetNode = targetNode.Children[nibble]

		depth += 4
	}
	targetNode = targetNode.Set(val, newVersion) // leaf
	tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	// recompute root hash
	for i := len(parentNodes) - 1; i >= 0; i-- {
		childNibble := key >> (int(tree.maxDepth) - (i+1)*4) & 0x0000000f
		targetNode = parentNodes[i].SetChildren(targetNode, int(childNibble))
		if targetNode.Extended() {
			targetNode.ComputeInternalHash(newVersion)
		}
		tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	}
	tree.root = targetNode
	return nil
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

	if key >= 1<<tree.maxDepth {
		return nil, ErrInvalidKey
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
	var neighborNode *TreeNode
	var depth uint8 = 4
	var proofs [][]byte
	var helpers []int

	for i := 0; i < int(tree.maxDepth)/4; i++ {
		path := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := path & 0x0000000f
		tree.extendNode(targetNode, nibble, path, depth)
		tree.extendNode(targetNode, nibble^1, path-nibble+nibble^1, depth)
		if neighborNode == nil {
			proofs = append(proofs, tree.nilHashes[depth-4])
		} else {
			proofs = append(proofs, neighborNode.Root())
		}
		helpers = append(helpers, int(path)/16%2)
		index := 0
		for j := 0; j < 3; j++ {
			// nibble / 8
			// nibble / 4
			// nibble / 2
			inc := int(nibble) / (1 << (3 - j))
			proofs = append(proofs, targetNode.Internals[(index+inc)^1])
			helpers = append(helpers, inc%2)
			index += 1 << (j + 1)
		}

		neighborNode = targetNode.Children[nibble^1]
		targetNode = targetNode.Children[nibble]
		depth += 4
	}
	if neighborNode == nil {
		proofs = append(proofs, tree.nilHashes[depth-4])
	} else {
		proofs = append(proofs, neighborNode.Root())
	}
	proofs = append(proofs, targetNode.Root())
	helpers = append(helpers, int(key)%2)

	return &Proof{
		MerkleProof: utils.ReverseBytes(proofs[1:]),
		ProofHelper: utils.ReverseInts(helpers[1:]),
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

	if len(proof.MerkleProof) != len(proof.ProofHelper)+1 {
		return false
	}

	root := tree.Root()
	node := proof.MerkleProof[0]
	for i := 1; i < len(proof.MerkleProof); i++ {
		switch proof.ProofHelper[i-1] {
		case 0:
			node = tree.hasher.Hash(node, proof.MerkleProof[i])
		case 1:
			node = tree.hasher.Hash(proof.MerkleProof[i], node)
		default:
			return false
		}
	}

	return bytes.Equal(root, node)
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
