package bsmt

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestTreeNode_Copy(t *testing.T) {
	hasher := &Hasher{sha256.New()}
	nilHashes := &nilHashes{[][]byte{
		[]byte("test0"),
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}}
	node := NewTreeNode(0, 0, nilHashes, hasher)
	copied := node.Copy()
	for i := 0; i < len(copied.Children); i++ {
		copied = copied.setChildren(NewTreeNode(4, uint64(i), nilHashes, hasher), i, 0)
	}
	copied.computeInternalHash()
	copied = copied.set(hasher.Hash(copied.Internals[0], copied.Internals[1]), 0)

	if bytes.Equal(node.Root(), copied.Root()) {
		t.Fatal("root should not be equal")
	}

	if len(node.Versions) != 0 {
		t.Fatal("length of node.version should be 0")
	}

	if len(copied.Versions) != 1 {
		t.Fatal("length of copied node.version should be 1")
	}

	for i := 0; i < len(node.Children); i++ {
		if node.Children[i] != nil {
			t.Fatalf("child %d of node should be nil", i)
		}
	}

	for i := 0; i < len(copied.Children); i++ {
		if copied.Children[i] == nil {
			t.Fatalf("child %d of copied node should not be nil", i)
		}
	}

	for i := 0; i < len(node.Internals); i++ {
		if bytes.Equal(node.Internals[i], copied.Internals[i]) {
			t.Fatalf("internal %d of node should be equal to copied node", i)
		}
	}
}
