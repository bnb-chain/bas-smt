package bsmt

import "hash"

func NewHasher(hasher hash.Hash) *Hasher {
	return &Hasher{
		hasher: hasher,
	}
}

type Hasher struct {
	hasher hash.Hash
}

func (h *Hasher) Hash(inputs ...[]byte) []byte {
	h.hasher.Reset()
	for i := range inputs {
		h.hasher.Write(inputs[i])
	}
	return h.hasher.Sum(nil)
}
