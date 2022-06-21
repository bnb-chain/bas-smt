package bsmt

type (
	Version          uint64
	SparseMerkleTree interface {
		Size() uint64
		Get(key uint64, version *Version) ([]byte, error)
		Set(key uint64, val []byte) error
		IsEmpty() bool
		Root() []byte
		GetProof(key uint64) (Proof, error)
		VerifyProof(key uint64, proof Proof) bool
		LatestVersion() Version
		Reset()
		Commit(recentVersion *Version) (Version, error)
		Rollback(version Version) error
	}
)
