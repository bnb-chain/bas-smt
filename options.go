package bsmt

// Option is a function that configures SMT.
type Option func(*BASSparseMerkleTree)

func BatchSizeLimit(limit int) Option {
	return func(smt *BASSparseMerkleTree) {
		smt.batchSizeLimit = limit
	}
}

func GCThreshold(threshold uint64) Option {
	return func(smt *BASSparseMerkleTree) {
		if smt.gcStatus != nil {
			smt.gcStatus.threshold = threshold
			smt.gcStatus.segment = threshold / 10
		}

	}
}
