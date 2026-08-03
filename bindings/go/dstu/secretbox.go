package dstu

// #include "dstu_core.h"
import "C"

import "runtime"

// SecretboxKey is an authenticated single-message encryption key (crypto_secretbox,
// Kalyna-256-256-GCM, internal random nonce).
type SecretboxKey struct {
	ptr *C.DstuSecretboxKey
}

// GenerateSecretboxKey generates a fresh key from the OS CSPRNG.
func GenerateSecretboxKey() (*SecretboxKey, error) {
	var out *C.DstuSecretboxKey
	if err := statusError(C.dstu_secretbox_key_generate(&out)); err != nil {
		return nil, err
	}
	return newSecretboxKey(out), nil
}

// SecretboxKeyFromBytes builds a key from exactly SecretboxKeyBytes bytes.
func SecretboxKeyFromBytes(key []byte) (*SecretboxKey, error) {
	if len(key) != SecretboxKeyBytes {
		return nil, &ArgumentError{"key must be exactly SecretboxKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return newSecretboxKey(C.dstu_secretbox_key_from_bytes(ptr)), nil
}

func newSecretboxKey(ptr *C.DstuSecretboxKey) *SecretboxKey {
	k := &SecretboxKey{ptr: ptr}
	runtime.SetFinalizer(k, (*SecretboxKey).Close)
	return k
}

// Bytes copies out this key's raw SecretboxKeyBytes-byte encoding.
func (k *SecretboxKey) Bytes() []byte {
	out := make([]byte, SecretboxKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_secretbox_key_bytes(k.ptr, outPtr)
	return out
}

// Seal encrypts and authenticates plaintext, drawing a fresh random nonce internally. The
// returned slice is exactly len(plaintext) + SecretboxOverhead bytes.
func (k *SecretboxKey) Seal(plaintext []byte) ([]byte, error) {
	outLen := len(plaintext) + SecretboxOverhead
	sealedOut := make([]byte, outLen)
	ptPtr, ptLen := cBytes(plaintext)
	sealedPtr, sealedCap := cBytes(sealedOut)
	var sealedLen C.size_t
	if err := statusError(C.dstu_secretbox_seal(k.ptr, ptPtr, ptLen, sealedPtr, sealedCap, &sealedLen)); err != nil {
		return nil, err
	}
	return sealedOut[:sealedLen], nil
}

// Open verifies and decrypts sealed as produced by Seal. Returns a *CryptoError on a tag
// mismatch or truncated input.
func (k *SecretboxKey) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < SecretboxOverhead {
		return nil, &CryptoError{"input is shorter than the minimum valid length for this construction"}
	}
	outLen := len(sealed) - SecretboxOverhead
	plaintextOut := make([]byte, outLen)
	sealedPtr, sealedLen := cBytes(sealed)
	ptPtr, ptCap := cBytes(plaintextOut)
	var ptLen C.size_t
	if err := statusError(C.dstu_secretbox_open(k.ptr, sealedPtr, sealedLen, ptPtr, ptCap, &ptLen)); err != nil {
		return nil, err
	}
	return plaintextOut[:ptLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *SecretboxKey) Close() error {
	if k.ptr != nil {
		C.dstu_secretbox_key_free(k.ptr)
		k.ptr = nil
		runtime.SetFinalizer(k, nil)
	}
	return nil
}
