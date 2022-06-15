package bsmt

// Option is a function that configures SMT.
type Option func(*BASSparseMerkleTree)

func BatchSizeLimit(limit int) Option {
	return func(smt *BASSparseMerkleTree) {
		smt.batchSizeLimit = limit
	}
}
