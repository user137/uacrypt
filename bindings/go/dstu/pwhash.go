package dstu

// #include "dstu_core.h"
// #include <stdlib.h>
import "C"

import (
	"bytes"
	"unsafe"
)

// HashPassword hashes password into a PHC-formatted string, using strength as the Argon2id cost
// preset. Returns a *CryptoError on OS CSPRNG or internal Argon2 failure.
func HashPassword(password []byte, strength PwhashStrength) (string, error) {
	out := make([]byte, PwhashStrBytes)
	pwPtr, pwLen := cBytes(password)
	outPtr, _ := cBytes(out)
	if err := statusError(C.dstu_pwhash_hash_password(pwPtr, pwLen, C.DstuPwhashStrength(strength), (*C.char)(unsafe.Pointer(outPtr)))); err != nil {
		return "", err
	}
	if nul := bytes.IndexByte(out, 0); nul >= 0 {
		out = out[:nul]
	}
	return string(out), nil
}

// VerifyPassword verifies password against a PHC string produced by HashPassword. Returns false
// for a wrong password or a malformed hash - there is nothing for a caller to branch differently
// on between those two cases.
func VerifyPassword(password []byte, hash string) bool {
	pwPtr, pwLen := cBytes(password)
	cHash := C.CString(hash)
	defer C.free(unsafe.Pointer(cHash))
	return bool(C.dstu_pwhash_verify_password(pwPtr, pwLen, cHash))
}
