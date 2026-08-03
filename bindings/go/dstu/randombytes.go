package dstu

// #include "dstu_core.h"
import "C"

// RandomBytes fills a fresh length-byte slice from the OS CSPRNG.
func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, &ArgumentError{"length must not be negative"}
	}
	buf := make([]byte, length)
	ptr, size := cBytes(buf)
	if err := statusError(C.dstu_randombytes_buf(ptr, size)); err != nil {
		return nil, err
	}
	return buf, nil
}
