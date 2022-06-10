package bsmt

type (
	Version          uint64
	SparseMerkleTree interface {
		Get(key uint64, version *Version) ([]byte, error)
		Set(key uint64, val []byte) error
		IsEmpty() bool
		Root() []byte
		GetProof(key uint64, version *Version) (*Proof, error)
		VerifyProof(proof *Proof, version *Version) bool
		LatestVersion() Version
		Reset()
		Commit() (Version, error)
		Rollback(version Version) error
	}
)
