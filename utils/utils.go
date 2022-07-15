package utils

import (
	"reflect"
	"unsafe"
)

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

// StringToBytes converts string to []byte without memory copy
func StringToBytes(str string) []byte {
	var buf []byte
	*(*string)(unsafe.Pointer(&buf)) = str
	(*reflect.SliceHeader)(unsafe.Pointer(&buf)).Cap = len(str)
	return buf
}

// StringToBytes converts []byte to string  without memory copy
func BytesToString(raw []byte) string {
	return *(*string)(unsafe.Pointer(&raw))
}
