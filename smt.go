package bsmt

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/rlp"
	sysMemory "github.com/pbnjay/memory"

	"github.com/bnb-chain/bas-smt/database"
	"github.com/bnb-chain/bas-smt/database/memory"
	"github.com/bnb-chain/bas-smt/utils"
)

var (
	latestVersionKey          = []byte(`latestVersion`)
	recentVersionNumberKey    = []byte(`recentVersionNumber`)
	storageFullTreeNodePrefix = []byte(`t`)
	sep                       = []byte(`:`)
)

func storageFullTreeNodeKey(depth uint8, path uint64) []byte {
	pathBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(pathBuf, path)
	return bytes.Join([][]byte{storageFullTreeNodePrefix, {depth}, pathBuf}, sep)
}

var _ SparseMerkleTree = (*BASSparseMerkleTree)(nil)

func NewBASSparseMerkleTree(hasher *Hasher, db database.TreeDB, maxDepth uint8, nilHash []byte,
	opts ...Option) (SparseMerkleTree, error) {

	if maxDepth == 0 || maxDepth%4 != 0 {
		return nil, ErrInvalidDepth
	}

	smt := &BASSparseMerkleTree{
		maxDepth:       maxDepth,
		journal:        map[journalKey]*TreeNode{},
		nilHashes:      constructNilHashes(maxDepth, nilHash, hasher),
		hasher:         hasher,
		batchSizeLimit: 100 * 1024,
		gcStatus: &gcStatus{
			threshold: sysMemory.TotalMemory() / 8,
			segment:   sysMemory.TotalMemory() / 8 / 10,
		},
	}

	for _, opt := range opts {
		opt(smt)
	}

	if db == nil {
		smt.db = memory.NewMemoryDB()
		smt.root = NewTreeNode(0, 0, smt.nilHashes, smt.hasher)
		return smt, nil
	}

	smt.db = db
	err := smt.initFromStorage()
	if err != nil {
		return nil, err
	}
	return smt, nil
}

func constructNilHashes(maxDepth uint8, nilHash []byte, hasher *Hasher) *nilHashes {
	hashes := make([][]byte, maxDepth+1)
	hashes[maxDepth] = nilHash
	for i := 1; i <= int(maxDepth); i++ {
		nHash := hasher.Hash(nilHash, nilHash)
		hashes[maxDepth-uint8(i)] = nHash
		nilHash = nHash
	}
	return &nilHashes{hashes}
}

type nilHashes struct {
	hashes [][]byte
}

func (h *nilHashes) Get(depth uint8) []byte {
	if len(h.hashes)-1 < int(depth) {
		return nil
	}
	return h.hashes[depth]
}

type journalKey struct {
	depth uint8
	path  uint64
}

// status for GC.
// In the Commit() stage, the version and releasable size will be recorded,
// the size of the current version tree exceeds the threshold and starts to trigger GC.
// The recorded size of the version is divided into 10 stages of threshold,
// each 10% is a partition, and if it exceeds 100%, it is recorded in the last partition.
// When the GC is triggered, the collection will start from the minimum collection size.
type gcStatus struct {
	versions        [10]Version
	sizes           [10]uint64
	threshold       uint64
	segment         uint64
	latestGCVersion Version
}

func (stat *gcStatus) add(version Version, size uint64) {
	if version == 0 || size == 0 {
		return
	}
	index := (size / stat.segment)
	if index > 9 {
		index = 9
	}
	stat.sizes[index] = size
	stat.versions[index] = version
}

func (stat *gcStatus) pop(currentSize uint64) Version {
	if currentSize < stat.threshold {
		return 0
	}

	var (
		except, maximal Version
	)
	for i := 0; i < len(stat.sizes); i++ {
		if stat.sizes[i] > 0 {
			maximal = stat.versions[i]
		}
		if except == 0 && currentSize-stat.sizes[i] < stat.threshold {
			except = stat.versions[i]
			stat.clean(i)
			break
		}
	}

	if except > 0 {
		stat.latestGCVersion = except
		return except
	}
	stat.clean(9)
	stat.latestGCVersion = maximal
	return maximal
}

func (stat *gcStatus) clean(index int) {
	for i := 0; i <= index; i++ {
		stat.sizes[i] = 0
		stat.versions[i] = 0
	}
}

type BASSparseMerkleTree struct {
	version          Version
	recentVersion    Version
	root             *TreeNode
	rootSize         uint64
	lastSaveRoot     *TreeNode
	lastSaveRootSize uint64
	journal          map[journalKey]*TreeNode
	maxDepth         uint8
	nilHashes        *nilHashes
	hasher           *Hasher
	db               database.TreeDB
	batchSizeLimit   int
	gcStatus         *gcStatus
}

func (tree *BASSparseMerkleTree) initFromStorage() error {
	tree.root = NewTreeNode(0, 0, tree.nilHashes, tree.hasher)
	// recovery version info
	buf, err := tree.db.Get(latestVersionKey)
	if errors.Is(err, database.ErrDatabaseNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	tree.version = Version(binary.BigEndian.Uint64(buf))
	buf, err = tree.db.Get(recentVersionNumberKey)
	if err != nil && !errors.Is(err, database.ErrDatabaseNotFound) {
		return err
	}
	if len(buf) > 0 {
		tree.recentVersion = Version(binary.BigEndian.Uint64(buf))
	}

	// recovery root node from storage
	rlpBytes, err := tree.db.Get(storageFullTreeNodeKey(0, 0))
	if errors.Is(err, database.ErrDatabaseNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	storageTreeNode := &StorageTreeNode{}
	err = rlp.DecodeBytes(rlpBytes, storageTreeNode)
	if err != nil {
		return err
	}
	tree.root = storageTreeNode.ToTreeNode(0, 0, tree.nilHashes, tree.hasher)
	length := len(tree.root.Versions)
	if length > 0 && tree.root.Versions[length-1].Ver != tree.version {
		return ErrUnexpected
	}

	tree.rootSize = tree.root.size()
	for i := 0; i < len(tree.root.Children); i++ {
		if tree.root.Children[i] != nil {
			tree.rootSize += uint64(versionSize * len(tree.root.Children[i].Versions))
		}
	}

	return nil
}

func (tree *BASSparseMerkleTree) extendNode(node *TreeNode, nibble, path uint64, depth uint8) error {
	if node.Children[nibble] != nil &&
		!node.Children[nibble].IsTemporary() {
		return nil
	}

	rlpBytes, err := tree.db.Get(storageFullTreeNodeKey(depth, path))
	if errors.Is(err, database.ErrDatabaseNotFound) {
		node.Children[nibble] = NewTreeNode(depth, path, tree.nilHashes, tree.hasher)
		return nil
	}
	if err != nil {
		return err
	}

	storageTreeNode := &StorageTreeNode{}
	err = rlp.DecodeBytes(rlpBytes, storageTreeNode)
	if err != nil {
		return err
	}
	node.Children[nibble] = storageTreeNode.ToTreeNode(
		depth, path, tree.nilHashes, tree.hasher)

	return nil
}

func (tree *BASSparseMerkleTree) Size() uint64 {
	return tree.rootSize
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

	// TODO: It will be further improved in the future to avoid reading from disk.
	rlpBytes, err := tree.db.Get(storageFullTreeNodeKey(tree.maxDepth, key))
	if errors.Is(err, database.ErrDatabaseNotFound) {
		return nil, ErrNodeNotFound
	}
	if err != nil {
		return nil, err
	}
	storageTreeNode := &StorageTreeNode{}
	err = rlp.DecodeBytes(rlpBytes, storageTreeNode)
	if err != nil {
		return nil, err
	}

	for i := len(storageTreeNode.Versions) - 1; i >= 0; i-- {
		if storageTreeNode.Versions[i].Ver <= *version {
			return storageTreeNode.Versions[i].Hash, nil
		}
	}

	return tree.nilHashes.Get(tree.maxDepth), nil
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
		nibble := path & 0x000000000000000f
		parentNodes = append(parentNodes, targetNode)
		if err := tree.extendNode(targetNode, nibble, path, depth); err != nil {
			return err
		}
		targetNode = targetNode.Children[nibble]

		depth += 4
	}
	targetNode = targetNode.set(val, newVersion) // leaf
	tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	// recompute root hash
	for i := len(parentNodes) - 1; i >= 0; i-- {
		childNibble := key >> (int(tree.maxDepth) - (i+1)*4) & 0x000000000000000f
		targetNode = parentNodes[i].setChildren(targetNode, int(childNibble), newVersion)

		tree.journal[journalKey{targetNode.depth, targetNode.path}] = targetNode
	}
	tree.root = targetNode
	return nil
}

func (tree *BASSparseMerkleTree) IsEmpty() bool {
	return bytes.Equal(tree.root.Root(), tree.nilHashes.Get(0))
}

func (tree *BASSparseMerkleTree) Root() []byte {
	return tree.root.Root()
}

func (tree *BASSparseMerkleTree) GetProof(key uint64) (Proof, error) {
	var proofs [][]byte
	if tree.IsEmpty() {
		proofs = append(proofs, tree.nilHashes.Get(tree.maxDepth))
		for i := tree.maxDepth; i > 0; i-- {
			proofs = append(proofs, tree.nilHashes.Get(i))
		}
		return proofs, nil
	}

	if key >= 1<<tree.maxDepth {
		return nil, ErrInvalidKey
	}

	targetNode := tree.root
	var neighborNode *TreeNode
	var depth uint8 = 4

	for i := 0; i < int(tree.maxDepth)/4; i++ {
		path := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := path & 0x000000000000000f
		if err := tree.extendNode(targetNode, nibble, path, depth); err != nil {
			return nil, err
		}
		if i > 0 { // ignore the root node
			if neighborNode == nil {
				proofs = append(proofs, tree.nilHashes.Get(depth-4))
			} else {
				proofs = append(proofs, neighborNode.Root())
			}
		}
		index := 0
		for j := 0; j < 3; j++ {
			// nibble / 8
			// nibble / 4
			// nibble / 2
			inc := int(nibble) / (1 << (3 - j))
			proofs = append(proofs, targetNode.Internals[(index+inc)^1])
			index += 1 << (j + 1)
		}

		neighborNode = targetNode.Children[nibble^1]
		targetNode = targetNode.Children[nibble]
		depth += 4
	}
	if neighborNode == nil {
		proofs = append(proofs, tree.nilHashes.Get(tree.maxDepth))
	} else {
		proofs = append(proofs, neighborNode.Root())
	}

	proofs = append(proofs, targetNode.Root())

	return utils.ReverseBytes(proofs), nil
}

func (tree *BASSparseMerkleTree) VerifyProof(key uint64, proof Proof) bool {
	if key >= 1<<tree.maxDepth {
		return false
	}

	var depth uint8 = 4
	var helpers []int

	for i := 0; i < int(tree.maxDepth)/4; i++ {
		path := key >> (int(tree.maxDepth) - (i+1)*4)
		nibble := path & 0x000000000000000f

		if i > 0 { // ignore the root node
			helpers = append(helpers, int(path)/16%2)
		}

		index := 0
		for j := 0; j < 3; j++ {
			// nibble / 8
			// nibble / 4
			// nibble / 2
			inc := int(nibble) / (1 << (3 - j))
			helpers = append(helpers, inc%2)
			index += 1 << (j + 1)
		}

		depth += 4
	}
	helpers = append(helpers, int(key)%2)
	helpers = utils.ReverseInts(helpers)
	if len(proof) != len(helpers)+1 {
		return false
	}

	root := tree.Root()
	node := proof[0]
	for i := 1; i < len(proof); i++ {
		switch helpers[i-1] {
		case 0:
			node = tree.hasher.Hash(node, proof[i])
		case 1:
			node = tree.hasher.Hash(proof[i], node)
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
	tree.rootSize = tree.lastSaveRootSize
}

func (tree *BASSparseMerkleTree) writeNode(db database.Batcher, fullNode *TreeNode, version Version, recentVersion *Version) (uint64, error) {
	changed := uint64(0)
	if fullNode.previousVersion() > tree.gcStatus.latestGCVersion {
		// If the previous version is greater than the last GC version,
		// the node has a high probability of existing in memory
		changed = versionSize
	} else {
		changed = fullNode.size()
	}
	// prune versions
	if recentVersion != nil {
		changed -= fullNode.Prune(*recentVersion)
	}

	// persist tree
	rlpBytes, err := rlp.EncodeToBytes(fullNode.ToStorageTreeNode())
	if err != nil {
		return changed, err
	}
	err = db.Set(storageFullTreeNodeKey(fullNode.depth, fullNode.path), rlpBytes)
	if err != nil {
		return changed, err
	}
	if db.ValueSize() > tree.batchSizeLimit {
		if err := db.Write(); err != nil {
			return changed, err
		}
		db.Reset()
	}

	return changed, nil
}

func (tree *BASSparseMerkleTree) Commit(recentVersion *Version) (Version, error) {
	newVersion := tree.version + 1
	if recentVersion != nil && *recentVersion >= tree.version {
		return tree.version, ErrVersionTooHigh
	}

	size := uint64(0)
	if tree.db != nil {
		// write tree nodes, prune old version
		batch := tree.db.NewBatch()
		for _, node := range tree.journal {
			changed, err := tree.writeNode(batch, node, newVersion, recentVersion)
			if err != nil {
				return tree.version, err
			}
			size += changed
		}
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newVersion))
		err := batch.Set(latestVersionKey, buf)
		if err != nil {
			return tree.version, err
		}

		if recentVersion != nil {
			buf = make([]byte, 8)
			binary.BigEndian.PutUint64(buf, uint64(*recentVersion))
			err = batch.Set(recentVersionNumberKey, buf)
			if err != nil {
				return tree.version, err
			}
		}

		err = batch.Write()
		if err != nil {
			return tree.version, err
		}
		batch.Reset()
	}

	tree.version = newVersion
	if recentVersion != nil {
		tree.recentVersion = *recentVersion
	}
	originSize := tree.rootSize
	currentSize := tree.rootSize + size
	if releaseVersion := tree.gcStatus.pop(currentSize); releaseVersion > 0 {
		currentSize = tree.root.release(releaseVersion)
	}
	tree.gcStatus.add(tree.recentVersion, currentSize)
	tree.journal = make(map[journalKey]*TreeNode)
	tree.lastSaveRoot = tree.root
	tree.lastSaveRootSize = originSize
	tree.rootSize = currentSize
	return newVersion, nil
}

func (tree *BASSparseMerkleTree) rollback(child *TreeNode, oldVersion Version, db database.Batcher) (error, uint64) {
	if child == nil {
		return nil, 0
	}
	// remove value nodes
	next, changed := child.Rollback(oldVersion)
	if !next {
		return nil, changed
	}

	// persist tree
	rlpBytes, err := rlp.EncodeToBytes(child.ToStorageTreeNode())
	if err != nil {
		return err, changed
	}
	err = db.Set(storageFullTreeNodeKey(child.depth, child.path), rlpBytes)
	if err != nil {
		return err, changed
	}
	if db.ValueSize() > tree.batchSizeLimit {
		if err := db.Write(); err != nil {
			return err, changed
		}
		db.Reset()
	}

	for _, subChild := range child.Children {
		err, subChanged := tree.rollback(subChild, oldVersion, db)
		if err != nil {
			return err, changed
		}
		changed += subChanged
	}

	return nil, changed
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
	size := tree.rootSize
	if tree.db != nil {
		batch := tree.db.NewBatch()
		err, changed := tree.rollback(tree.root, version, batch)
		if err != nil {
			return err
		}
		size -= changed
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(newVersion))
		err = batch.Set(latestVersionKey, buf)
		if err != nil {
			return err
		}

		err = batch.Write()
		if err != nil {
			return err
		}
		batch.Reset()
	}

	tree.version = newVersion
	tree.rootSize = size
	return nil
}
