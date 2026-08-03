package dstu

// #include "dstu_core.h"
import "C"

import "runtime"

// KdfMasterKey is a Kupyna-KDF master key (crypto_kdf).
type KdfMasterKey struct {
	ptr *C.DstuKdfMasterKey
}

// GenerateKdfMasterKey generates a fresh master key from the OS CSPRNG.
func GenerateKdfMasterKey() (*KdfMasterKey, error) {
	var out *C.DstuKdfMasterKey
	if err := statusError(C.dstu_kdf_master_key_generate(&out)); err != nil {
		return nil, err
	}
	return newKdfMasterKey(out), nil
}

// KdfMasterKeyFromBytes builds a master key from exactly KdfKeyBytes bytes.
func KdfMasterKeyFromBytes(key []byte) (*KdfMasterKey, error) {
	if len(key) != KdfKeyBytes {
		return nil, &ArgumentError{"key must be exactly KdfKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return newKdfMasterKey(C.dstu_kdf_master_key_from_bytes(ptr)), nil
}

func newKdfMasterKey(ptr *C.DstuKdfMasterKey) *KdfMasterKey {
	k := &KdfMasterKey{ptr: ptr}
	runtime.SetFinalizer(k, (*KdfMasterKey).Close)
	return k
}

// Bytes copies out this key's raw KdfKeyBytes-byte encoding.
func (k *KdfMasterKey) Bytes() []byte {
	out := make([]byte, KdfKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_kdf_master_key_bytes(k.ptr, outPtr)
	return out
}

// DeriveSubkey derives a KdfSubkeyBytes-byte subkey from subkeyID/context (exactly
// KdfContextBytes bytes).
func (k *KdfMasterKey) DeriveSubkey(subkeyID uint64, context []byte) ([]byte, error) {
	if len(context) != KdfContextBytes {
		return nil, &ArgumentError{"context must be exactly KdfContextBytes bytes"}
	}
	out := make([]byte, KdfSubkeyBytes)
	ctxPtr, _ := cBytes(context)
	outPtr, _ := cBytes(out)
	C.dstu_kdf_derive_subkey(k.ptr, C.uint64_t(subkeyID), ctxPtr, outPtr)
	return out, nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *KdfMasterKey) Close() error {
	if k.ptr != nil {
		C.dstu_kdf_master_key_free(k.ptr)
		k.ptr = nil
		runtime.SetFinalizer(k, nil)
	}
	return nil
}
