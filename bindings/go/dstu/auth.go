package dstu

// #include "dstu_core.h"
import "C"

// AuthKey is a Kupyna-KMAC message-authentication key (crypto_auth).
//
// No runtime.SetFinalizer backstop: attaching one would let the GC treat k as unreachable (and
// free it) while a C.dstu_* call using k.ptr is still in flight, since the last Go-side reference
// to k is the pointer argument itself, not k - a use-after-free/double-free race on secret key
// material invisible to any test that keeps k reachable via defer. Close() is the only way to
// free; call it explicitly (or via defer) once done.
type AuthKey struct {
	ptr *C.DstuAuthKey
}

// GenerateAuthKey generates a fresh key from the OS CSPRNG.
func GenerateAuthKey() (*AuthKey, error) {
	var out *C.DstuAuthKey
	if err := statusError(C.dstu_auth_key_generate(&out)); err != nil {
		return nil, err
	}
	return &AuthKey{ptr: out}, nil
}

// AuthKeyFromBytes builds a key from exactly AuthKeyBytes bytes.
func AuthKeyFromBytes(key []byte) (*AuthKey, error) {
	if len(key) != AuthKeyBytes {
		return nil, &ArgumentError{"key must be exactly AuthKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return &AuthKey{ptr: C.dstu_auth_key_from_bytes(ptr)}, nil
}

// Bytes copies out this key's raw AuthKeyBytes-byte encoding.
func (k *AuthKey) Bytes() []byte {
	out := make([]byte, AuthKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_auth_key_bytes(k.ptr, outPtr)
	return out
}

// Compute computes the MAC of message under this key.
func (k *AuthKey) Compute(message []byte) []byte {
	tag := make([]byte, AuthTagBytes)
	msgPtr, msgLen := cBytes(message)
	tagPtr, _ := cBytes(tag)
	C.dstu_auth(k.ptr, msgPtr, msgLen, tagPtr)
	return tag
}

// Verify verifies tag against message under this key. Returns a *CryptoError on a mismatch.
func (k *AuthKey) Verify(message, tag []byte) error {
	if len(tag) != AuthTagBytes {
		return &ArgumentError{"tag must be exactly AuthTagBytes bytes"}
	}
	msgPtr, msgLen := cBytes(message)
	tagPtr, _ := cBytes(tag)
	return statusError(C.dstu_auth_verify(k.ptr, msgPtr, msgLen, tagPtr))
}

// Close releases the underlying native key. Safe to call more than once.
func (k *AuthKey) Close() error {
	if k.ptr != nil {
		C.dstu_auth_key_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
