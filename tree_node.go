package bsmt

func NewTreeNode(depth uint8, path uint64, nilHashes map[uint8][]byte, hasher *Hasher) *TreeNode {
	treeNode := &TreeNode{
		nilHash:      nilHashes[depth],
		nilChildHash: nilHashes[depth+4],
		path:         path,
		depth:        depth,
		hasher:       hasher,
	}
	for i := 0; i < 2; i++ {
		treeNode.Internals[i] = nilHashes[depth+1]
	}
	for i := 2; i < 6; i++ {
		treeNode.Internals[i] = nilHashes[depth+2]
	}
	for i := 6; i < 13; i++ {
		treeNode.Internals[i] = nilHashes[depth+3]
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
}

func (node *TreeNode) Root() []byte {
	if len(node.Versions) == 0 {
		return node.nilHash
	}
	return node.Versions[len(node.Versions)-1].Hash
}

func (node *TreeNode) Set(hash []byte, version Version) *TreeNode {
	copied := node.Copy()
	copied.Versions = append(node.Versions, &VersionInfo{
		Ver:  version,
		Hash: hash,
	})

	return copied
}

func (node *TreeNode) SetChildren(child *TreeNode, nibble int) *TreeNode {
	copied := node.Copy()
	copied.Children[nibble] = child
	return copied
}

// top-down
func (node *TreeNode) ComputeInternalHash(version Version) {
	// leaf node first
	for i := 0; i < 15; i += 2 {
		left, right := node.nilChildHash, node.nilChildHash
		if node.Children[i] != nil {
			left = node.Children[i].Root()
		}
		if node.Children[i+1] != nil {
			right = node.Children[i+1].Root()
		}
		node.Internals[5+i/2] = node.hasher.Hash(left, right)
	}
	// internal node
	for i := 13; i > 1; i -= 2 {
		node.Internals[i/2-1] = node.hasher.Hash(node.Internals[i-1], node.Internals[i])
	}
	// update current root node
	node.Versions = append(node.Versions, &VersionInfo{
		Ver:  version,
		Hash: node.hasher.Hash(node.Internals[0], node.Internals[1]),
	})
}

func (node *TreeNode) Copy() *TreeNode {
	return &TreeNode{
		Children:  node.Children,
		Internals: node.Internals,
		Versions:  node.Versions,
		depth:     node.depth,
		hasher:    node.hasher,
	}
}

func (node *TreeNode) Prune(oldestVersion Version) {
	i := 0
	for ; i < len(node.Versions); i++ {
		if node.Versions[i].Ver >= oldestVersion {
			break
		}
	}
	node.Versions = node.Versions[i:]
}

func (node *TreeNode) Rollback(targetVersion Version) bool {
	next := false
	if len(node.Versions) == 0 {
		return false
	}
	i := len(node.Versions) - 1
	for ; i > 0; i-- {
		if node.Versions[i].Ver <= targetVersion {
			break
		}
		next = true
	}
	node.Versions = node.Versions[:i]

	return next
}

func (node *TreeNode) ToStorageTreeNode() *StorageTreeNode {
	return &StorageTreeNode{
		Internals: node.Internals,
		Versions:  node.Versions,
	}
}

type VersionInfo struct {
	Ver  Version
	Hash []byte
}

type StorageTreeNode struct {
	Internals [14]InternalNode `rlp:"optional"`
	Versions  []*VersionInfo   `rlp:"optional"`
}

func (node *StorageTreeNode) ToTreeNode(depth uint8, path uint64, nilHashes map[uint8][]byte, hasher *Hasher) *TreeNode {
	return &TreeNode{
		Internals:    node.Internals,
		Versions:     node.Versions,
		nilHash:      nilHashes[depth],
		nilChildHash: nilHashes[depth+4],
		path:         path,
		depth:        depth,
		hasher:       hasher,
	}
}
