package bsmt

// Option is a function that configures SMT.
type Option func(*BASSparseMerkleTree)

func InitializeVersion(version Version) Option {
	return func(smt *BASSparseMerkleTree) {
		smt.version = version
	}
}

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
