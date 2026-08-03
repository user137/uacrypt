package dstu

// #include "dstu_core.h"
import "C"

import "unsafe"

// Memzero overwrites buf with zero bytes in a way the compiler cannot optimize away as dead -
// libsodium's sodium_memzero equivalent. Secret material copied out into a caller-owned buffer
// (e.g. SigningKey.Bytes) is the caller's own responsibility to wipe once done; the native
// zeroize-on-drop wrapped by every opaque handle's Close cannot reach a copy made outside it.
func Memzero(buf []byte) {
	ptr, size := cBytes(buf)
	C.dstu_memzero(unsafe.Pointer(ptr), size)
}
