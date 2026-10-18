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
	if err := statusError(C.dstu_pwhash_hash_password(pwPtr, pwLen, C.uint32_t(strength), (*C.char)(unsafe.Pointer(outPtr)))); err != nil {
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

// DeriveKey derives a PwhashKeyBytes-byte key from password and a PwhashSaltBytes-byte salt -
// libsodium's crypto_pwhash (Argon2id v1.3), byte for byte (T-269). Runs on the calling
// goroutine. Returns an *ArgumentError for a wrong-length salt or an unknown strength, a
// *CryptoError if Argon2 cannot get its memory.
func DeriveKey(password, salt []byte, strength PwhashStrength) ([]byte, error) {
	if len(salt) != PwhashSaltBytes {
		return nil, &ArgumentError{"salt must be exactly 16 bytes"}
	}
	key := make([]byte, PwhashKeyBytes)
	pwPtr, pwLen := cBytes(password)
	saltPtr, _ := cBytes(salt)
	keyPtr, _ := cBytes(key)
	if err := statusError(C.dstu_pwhash_derive_key(pwPtr, pwLen, saltPtr, C.uint32_t(strength), keyPtr)); err != nil {
		return nil, err
	}
	return key, nil
}
