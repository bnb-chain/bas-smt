package utils

// CopyBytes returns an exact copy of the provided bytes.
func CopyBytes(b []byte) (copiedBytes []byte) {
	if b == nil {
		return nil
	}
	copiedBytes = make([]byte, len(b))
	copy(copiedBytes, b)

	return
}

func ReverseBytes(value [][]byte) [][]byte {
	for i, j := 0, len(value)-1; i < j; i, j = i+1, j-1 {
		value[i], value[j] = value[j], value[i]
	}
	return value
}

func ReverseInts(value []int) []int {
	for i, j := 0, len(value)-1; i < j; i, j = i+1, j-1 {
		value[i], value[j] = value[j], value[i]
	}
	return value
}

func BinaryToDecimal(value []int) uint64 {
	var result uint64
	length := len(value)
	for i := 0; i < length; i++ {
		result += uint64(value[i]) * (1 << (length - 1 - i))
	}
	return result
}
