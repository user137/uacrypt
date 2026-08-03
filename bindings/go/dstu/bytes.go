package dstu

// #include "dstu_core.h"
import "C"

import "unsafe"

// cBytes returns a pointer to b's first byte and its length as a C size_t. Returns (nil, 0) for
// a nil or empty slice - &b[0] on an empty slice panics, and this header documents zero-length
// input as legal throughout (a NULL pointer with length 0 is a no-op, never a NULL pointer with a
// nonzero length).
func cBytes(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}
