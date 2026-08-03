package dstu

// #include "dstu_core.h"
import "C"

import "runtime"

// StreamCipherKey is an unauthenticated keystream cipher key (crypto_stream, Strumok-256,
// internal random IV). Decrypt never fails on tampered input - there is no tag to verify, and a
// modified sealed message silently decrypts to different, wrong plaintext instead of erroring.
type StreamCipherKey struct {
	ptr *C.DstuStreamKey
}

// GenerateStreamCipherKey generates a fresh key from the OS CSPRNG.
func GenerateStreamCipherKey() (*StreamCipherKey, error) {
	var out *C.DstuStreamKey
	if err := statusError(C.dstu_stream_key_generate(&out)); err != nil {
		return nil, err
	}
	return newStreamCipherKey(out), nil
}

// StreamCipherKeyFromBytes builds a key from exactly StreamKeyBytes bytes.
func StreamCipherKeyFromBytes(key []byte) (*StreamCipherKey, error) {
	if len(key) != StreamKeyBytes {
		return nil, &ArgumentError{"key must be exactly StreamKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return newStreamCipherKey(C.dstu_stream_key_from_bytes(ptr)), nil
}

func newStreamCipherKey(ptr *C.DstuStreamKey) *StreamCipherKey {
	k := &StreamCipherKey{ptr: ptr}
	runtime.SetFinalizer(k, (*StreamCipherKey).Close)
	return k
}

// Bytes copies out this key's raw StreamKeyBytes-byte encoding.
func (k *StreamCipherKey) Bytes() []byte {
	out := make([]byte, StreamKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_stream_key_bytes(k.ptr, outPtr)
	return out
}

// Encrypt XORs plaintext with a fresh keystream, drawing a random IV internally. The returned
// slice is exactly len(plaintext) + StreamOverhead bytes.
func (k *StreamCipherKey) Encrypt(plaintext []byte) ([]byte, error) {
	outLen := len(plaintext) + StreamOverhead
	sealedOut := make([]byte, outLen)
	ptPtr, ptLen := cBytes(plaintext)
	sealedPtr, sealedCap := cBytes(sealedOut)
	var sealedLen C.size_t
	if err := statusError(C.dstu_stream_encrypt(k.ptr, ptPtr, ptLen, sealedPtr, sealedCap, &sealedLen)); err != nil {
		return nil, err
	}
	return sealedOut[:sealedLen], nil
}

// Decrypt reverses Encrypt. Returns a *CryptoError only if sealed is shorter than
// StreamOverhead - there is no tag, so tampered input decrypts silently to wrong plaintext.
func (k *StreamCipherKey) Decrypt(sealed []byte) ([]byte, error) {
	if len(sealed) < StreamOverhead {
		return nil, &CryptoError{"input is shorter than the minimum valid length for this construction"}
	}
	outLen := len(sealed) - StreamOverhead
	plaintextOut := make([]byte, outLen)
	sealedPtr, sealedLen := cBytes(sealed)
	ptPtr, ptCap := cBytes(plaintextOut)
	var ptLen C.size_t
	if err := statusError(C.dstu_stream_decrypt(k.ptr, sealedPtr, sealedLen, ptPtr, ptCap, &ptLen)); err != nil {
		return nil, err
	}
	return plaintextOut[:ptLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *StreamCipherKey) Close() error {
	if k.ptr != nil {
		C.dstu_stream_key_free(k.ptr)
		k.ptr = nil
		runtime.SetFinalizer(k, nil)
	}
	return nil
}
