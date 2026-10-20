package dstu

// #include "dstu_core.h"
import "C"

// Box384SecretKey is a crypto_box384 secret key - the l(p)=384 (E384/1) sibling of BoxSecretKey
// (T-297). Same shape, a distinct type - not interchangeable with crypto_box.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type Box384SecretKey struct {
	ptr *C.DstuBox384SecretKey
}

// GenerateBox384SecretKey generates a fresh secret key from the OS CSPRNG.
func GenerateBox384SecretKey() (*Box384SecretKey, error) {
	var out *C.DstuBox384SecretKey
	if err := statusError(C.dstu_box384_secretkey_generate(&out)); err != nil {
		return nil, err
	}
	return &Box384SecretKey{ptr: out}, nil
}

// Box384SecretKeyFromBytes builds a secret key from a big-endian Box384SecretKeyBytes-byte
// scalar. Returns a *ArgumentError if it's outside the valid range {2, ..., n-2}.
func Box384SecretKeyFromBytes(bytes []byte) (*Box384SecretKey, error) {
	if len(bytes) != Box384SecretKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly Box384SecretKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBox384SecretKey
	if err := statusError(C.dstu_box384_secretkey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &Box384SecretKey{ptr: out}, nil
}

// Bytes copies out this key's big-endian Box384SecretKeyBytes-byte scalar encoding. The caller is
// responsible for wiping the returned slice once done (see Memzero) - this copies secret material
// into a Go-owned buffer the wrapped native key's own zeroize-on-drop cannot reach.
func (k *Box384SecretKey) Bytes() []byte {
	out := make([]byte, Box384SecretKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box384_secretkey_bytes(k.ptr, outPtr)
	return out
}

// PublicKey derives the public key for this secret key - safe to share/publish.
func (k *Box384SecretKey) PublicKey() *Box384PublicKey {
	return &Box384PublicKey{ptr: C.dstu_box384_secretkey_public_key(k.ptr)}
}

// Open decrypts sealed as produced by Box384PublicKey.Seal. Returns a *CryptoError if
// authentication fails (wrong key, or any tampered wire segment - deliberately not distinguished
// further, see dstu_core::crypto_box384::OpenError's own doc comment) or sealed is too short to be
// valid.
func (k *Box384SecretKey) Open(sealed []byte) ([]byte, error) {
	// The core checks the version byte before the length (T-269): a short 0.4-0.6 blob is
	// reported as an unsupported version, not as too short.
	outLen := max(0, len(sealed)-Box384OpenMinOverhead)
	plaintextOut := make([]byte, outLen)
	sealedPtr, sealedLen := cBytes(sealed)
	ptPtr, ptCap := cBytes(plaintextOut)
	var ptLen C.size_t
	if err := statusError(C.dstu_box384_open(k.ptr, sealedPtr, sealedLen, ptPtr, ptCap, &ptLen)); err != nil {
		return nil, err
	}
	return plaintextOut[:ptLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *Box384SecretKey) Close() error {
	if k.ptr != nil {
		C.dstu_box384_secretkey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}

// Box384PublicKey is a crypto_box384 public key - a curve point's x-coordinate only, see
// dstu_core::crypto_box384's own module doc for why this compression is safe.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type Box384PublicKey struct {
	ptr *C.DstuBox384PublicKey
}

// Box384PublicKeyFromBytes builds a public key from its compressed Box384PublicKeyBytes-byte
// x-coordinate encoding. Returns a *ArgumentError if it isn't a valid field element, or doesn't
// reconstruct to a point inside the base point's own prime-order subgroup.
func Box384PublicKeyFromBytes(bytes []byte) (*Box384PublicKey, error) {
	if len(bytes) != Box384PublicKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly Box384PublicKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBox384PublicKey
	if err := statusError(C.dstu_box384_publickey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &Box384PublicKey{ptr: out}, nil
}

// Bytes copies out this key's Box384PublicKeyBytes-byte encoding - not secret, no wiping needed
// afterward.
func (k *Box384PublicKey) Bytes() []byte {
	out := make([]byte, Box384PublicKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box384_publickey_bytes(k.ptr, outPtr)
	return out
}

// Seal encrypts message (any length) to the holder of this public key, drawing a fresh random
// seed and ephemeral key internally.
func (k *Box384PublicKey) Seal(message []byte) ([]byte, error) {
	var outLen C.size_t
	if err := statusError(C.dstu_box384_sealed_len(C.size_t(len(message)), &outLen)); err != nil {
		return nil, err
	}
	sealedOut := make([]byte, outLen)
	msgPtr, msgLen := cBytes(message)
	sealedPtr, sealedCap := cBytes(sealedOut)
	var sealedLen C.size_t
	if err := statusError(C.dstu_box384_seal(k.ptr, msgPtr, msgLen, sealedPtr, sealedCap, &sealedLen)); err != nil {
		return nil, err
	}
	return sealedOut[:sealedLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *Box384PublicKey) Close() error {
	if k.ptr != nil {
		C.dstu_box384_publickey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
