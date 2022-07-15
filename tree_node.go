package bsmt

func NewTreeNode(depth uint8, path uint64, nilHashes *nilHashes, hasher *Hasher) *TreeNode {
	treeNode := &TreeNode{
		nilHash:      nilHashes.Get(depth),
		nilChildHash: nilHashes.Get(depth + 4),
		path:         path,
		depth:        depth,
		hasher:       hasher,
		extended:     true,
	}
	for i := 0; i < 2; i++ {
		treeNode.Internals[i] = nilHashes.Get(depth + 1)
	}
	for i := 2; i < 6; i++ {
		treeNode.Internals[i] = nilHashes.Get(depth + 2)
	}
	for i := 6; i < 14; i++ {
		treeNode.Internals[i] = nilHashes.Get(depth + 3)
	}

	return treeNode
}

type InternalNode []byte

type TreeNode struct {
	Children  [16]*TreeNode
	Internals [14]InternalNode
	Versions  []*VersionInfo

	nilHash      []byte
	nilChildHash []byte
	path         uint64
	depth        uint8
	hasher       *Hasher
	extended     bool
}

func (node *TreeNode) Root() []byte {
	if len(node.Versions) == 0 {
		return node.nilHash
	}
	return node.Versions[len(node.Versions)-1].Hash
}

func (node *TreeNode) set(hash []byte, version Version) *TreeNode {
	copied := node.Copy()
	copied.newVersion(&VersionInfo{
		Ver:  version,
		Hash: hash,
	})

	return copied
}

func (node *TreeNode) newVersion(version *VersionInfo) {
	if len(node.Versions) > 0 && node.Versions[len(node.Versions)-1].Ver == version.Ver {
		// a new version already exists, overwrite it
		node.Versions[len(node.Versions)-1] = version
		return
	}
	node.Versions = append(node.Versions, version)
}

func (node *TreeNode) setChildren(child *TreeNode, nibble int, version Version) *TreeNode {
	copied := node.Copy()
	copied.Children[nibble] = child

	left, right := copied.nilChildHash, copied.nilChildHash
	switch nibble % 2 {
	case 0:
		if copied.Children[nibble] != nil {
			left = copied.Children[nibble].Root()
		}
		if copied.Children[nibble^1] != nil {
			right = copied.Children[nibble^1].Root()
		}
	case 1:
		if copied.Children[nibble] != nil {
			right = copied.Children[nibble].Root()
		}
		if copied.Children[nibble^1] != nil {
			left = copied.Children[nibble^1].Root()
		}
	}
	prefix := 6
	for i := 4; i >= 1; i >>= 1 {
		nibble = nibble / 2
		copied.Internals[prefix+nibble] = copied.hasher.Hash(left, right)
		switch nibble % 2 {
		case 0:
			left = copied.Internals[prefix+nibble]
			right = copied.Internals[prefix+nibble^1]
		case 1:
			right = copied.Internals[prefix+nibble]
			left = copied.Internals[prefix+nibble^1]
		}
		prefix = prefix - i
	}
	// update current root node
	copied.newVersion(&VersionInfo{
		Ver:  version,
		Hash: copied.hasher.Hash(copied.Internals[0], copied.Internals[1]),
	})
	return copied
}

// Recompute all internal hashes
func (node *TreeNode) computeInternalHash() {
	// leaf node
	for i := 0; i < 15; i += 2 {
		left, right := node.nilChildHash, node.nilChildHash
		if node.Children[i] != nil {
			left = node.Children[i].Root()
		}
		if node.Children[i+1] != nil {
			right = node.Children[i+1].Root()
		}
		node.Internals[6+i/2] = node.hasher.Hash(left, right)
	}
	// internal node
	for i := 13; i > 1; i -= 2 {
		node.Internals[i/2-1] = node.hasher.Hash(node.Internals[i-1], node.Internals[i])
	}
}

func (node *TreeNode) Extended() bool {
	return node.extended
}

func (node *TreeNode) Copy() *TreeNode {
	return &TreeNode{
		Children:     node.Children,
		Internals:    node.Internals,
		Versions:     node.Versions,
		nilHash:      node.nilHash,
		nilChildHash: node.nilChildHash,
		path:         node.path,
		depth:        node.depth,
		hasher:       node.hasher,
		extended:     node.extended,
	}
}

func (node *TreeNode) Prune(oldestVersion Version) {
	if len(node.Versions) <= 1 {
		return
	}
	i := 0
	for ; i < len(node.Versions)-1; i++ {
		if node.Versions[i].Ver >= oldestVersion {
			break
		}
	}

	if i > 0 && node.Versions[i].Ver > oldestVersion {
		node.Versions = node.Versions[i-1:]
		return
	}

	node.Versions = node.Versions[i:]
}

func (node *TreeNode) Rollback(targetVersion Version) bool {
	if len(node.Versions) == 0 {
		return false
	}
	var next bool
	i := len(node.Versions) - 1
	for ; i >= 0; i-- {
		if node.Versions[i].Ver <= targetVersion {
			break
		}
		next = true
	}
	node.Versions = node.Versions[:i+1]
	node.computeInternalHash()
	return next
}

func (node *TreeNode) ToStorageTreeNode() *StorageTreeNode {
	var children [16]*StorageLeafNode
	for i := 0; i < 16; i++ {
		if node.Children[i] != nil {
			children[i] = &StorageLeafNode{node.Children[i].Versions}
		}
	}
	return &StorageTreeNode{
		Children:  children,
		Internals: node.Internals,
		Versions:  node.Versions,
	}
}

type VersionInfo struct {
	Ver  Version
	Hash []byte
}

type StorageLeafNode struct {
	Versions []*VersionInfo `rlp:"optional"`
}

type StorageTreeNode struct {
	Children  [16]*StorageLeafNode `rlp:"optional"`
	Internals [14]InternalNode     `rlp:"optional"`
	Versions  []*VersionInfo       `rlp:"optional"`
}

func (node *StorageTreeNode) ToTreeNode(depth uint8, path uint64, nilHashes *nilHashes, hasher *Hasher) *TreeNode {
	treeNode := &TreeNode{
		Internals:    node.Internals,
		Versions:     node.Versions,
		nilHash:      nilHashes.Get(depth),
		nilChildHash: nilHashes.Get(depth + 4),
		path:         path,
		depth:        depth,
		hasher:       hasher,
		extended:     true,
	}
	for i := 0; i < 16; i++ {
		if node.Children[i] != nil {
			treeNode.Children[i] = &TreeNode{
				Versions:     node.Children[i].Versions,
				nilHash:      nilHashes.Get(depth + 4),
				nilChildHash: nilHashes.Get(depth + 8),
			}
		}
	}

	return treeNode
}
