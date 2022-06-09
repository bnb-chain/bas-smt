package bsmt

import "hash"

type Hasher struct {
	hasher hash.Hash
}

func (h *Hasher) Hash(inputs ...[]byte) []byte {
	for _, input := range inputs {
		h.hasher.Write(input)
	}
	defer h.hasher.Reset()
	return h.hasher.Sum(nil)
}
