package dstu

// #include "dstu_core.h"
import "C"

// BoxSecretKey is a crypto_box secret key (hybrid via KDF over hazmat::dstu9041, D-169).
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type BoxSecretKey struct {
	ptr *C.DstuBoxSecretKey
}

// GenerateBoxSecretKey generates a fresh secret key from the OS CSPRNG.
func GenerateBoxSecretKey() (*BoxSecretKey, error) {
	var out *C.DstuBoxSecretKey
	if err := statusError(C.dstu_box_secretkey_generate(&out)); err != nil {
		return nil, err
	}
	return &BoxSecretKey{ptr: out}, nil
}

// BoxSecretKeyFromBytes builds a secret key from a big-endian BoxSecretKeyBytes-byte scalar.
// Returns a *ArgumentError if it's outside the valid range {2, ..., n-2}.
func BoxSecretKeyFromBytes(bytes []byte) (*BoxSecretKey, error) {
	if len(bytes) != BoxSecretKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly BoxSecretKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBoxSecretKey
	if err := statusError(C.dstu_box_secretkey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &BoxSecretKey{ptr: out}, nil
}

// Bytes copies out this key's big-endian BoxSecretKeyBytes-byte scalar encoding. The caller is
// responsible for wiping the returned slice once done (see Memzero) - this copies secret material
// into a Go-owned buffer the wrapped native key's own zeroize-on-drop cannot reach.
func (k *BoxSecretKey) Bytes() []byte {
	out := make([]byte, BoxSecretKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box_secretkey_bytes(k.ptr, outPtr)
	return out
}

// PublicKey derives the public key for this secret key - safe to share/publish.
func (k *BoxSecretKey) PublicKey() *BoxPublicKey {
	return &BoxPublicKey{ptr: C.dstu_box_secretkey_public_key(k.ptr)}
}

// Open decrypts sealed as produced by BoxPublicKey.Seal. Returns a *CryptoError if authentication
// fails (wrong key, or any tampered wire segment - deliberately not distinguished further, see
// dstu_core::crypto_box::OpenError's own doc comment) or sealed is too short to be valid.
func (k *BoxSecretKey) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < BoxSealOverhead {
		return nil, &CryptoError{"input is shorter than the minimum valid length for this construction"}
	}
	outLen := len(sealed) - BoxSealOverhead
	plaintextOut := make([]byte, outLen)
	sealedPtr, sealedLen := cBytes(sealed)
	ptPtr, ptCap := cBytes(plaintextOut)
	var ptLen C.size_t
	if err := statusError(C.dstu_box_open(k.ptr, sealedPtr, sealedLen, ptPtr, ptCap, &ptLen)); err != nil {
		return nil, err
	}
	return plaintextOut[:ptLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *BoxSecretKey) Close() error {
	if k.ptr != nil {
		C.dstu_box_secretkey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}

// BoxPublicKey is a crypto_box public key - a curve point's x-coordinate only, see
// dstu_core::crypto_box's own module doc for why this compression is safe.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type BoxPublicKey struct {
	ptr *C.DstuBoxPublicKey
}

// BoxPublicKeyFromBytes builds a public key from its compressed BoxPublicKeyBytes-byte
// x-coordinate encoding. Returns a *ArgumentError if it isn't a valid field element, or doesn't
// reconstruct to a point inside the base point's own prime-order subgroup.
func BoxPublicKeyFromBytes(bytes []byte) (*BoxPublicKey, error) {
	if len(bytes) != BoxPublicKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly BoxPublicKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBoxPublicKey
	if err := statusError(C.dstu_box_publickey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &BoxPublicKey{ptr: out}, nil
}

// Bytes copies out this key's BoxPublicKeyBytes-byte encoding - not secret, no wiping needed
// afterward.
func (k *BoxPublicKey) Bytes() []byte {
	out := make([]byte, BoxPublicKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box_publickey_bytes(k.ptr, outPtr)
	return out
}

// Seal encrypts message (any length) to the holder of this public key, drawing a fresh random
// seed and ephemeral key internally.
func (k *BoxPublicKey) Seal(message []byte) ([]byte, error) {
	outLen := len(message) + BoxSealOverhead
	sealedOut := make([]byte, outLen)
	msgPtr, msgLen := cBytes(message)
	sealedPtr, sealedCap := cBytes(sealedOut)
	var sealedLen C.size_t
	if err := statusError(C.dstu_box_seal(k.ptr, msgPtr, msgLen, sealedPtr, sealedCap, &sealedLen)); err != nil {
		return nil, err
	}
	return sealedOut[:sealedLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *BoxPublicKey) Close() error {
	if k.ptr != nil {
		C.dstu_box_publickey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
