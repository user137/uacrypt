package dstu

// #include "dstu_core.h"
import "C"

// Box512SecretKey is a crypto_box512 secret key - the l(p)=512 (E512/1) sibling of BoxSecretKey
// (T-193/T-204). Same shape, a distinct type - not interchangeable with crypto_box.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type Box512SecretKey struct {
	ptr *C.DstuBox512SecretKey
}

// GenerateBox512SecretKey generates a fresh secret key from the OS CSPRNG.
func GenerateBox512SecretKey() (*Box512SecretKey, error) {
	var out *C.DstuBox512SecretKey
	if err := statusError(C.dstu_box512_secretkey_generate(&out)); err != nil {
		return nil, err
	}
	return &Box512SecretKey{ptr: out}, nil
}

// Box512SecretKeyFromBytes builds a secret key from a big-endian Box512SecretKeyBytes-byte
// scalar. Returns a *ArgumentError if it's outside the valid range {2, ..., n-2}.
func Box512SecretKeyFromBytes(bytes []byte) (*Box512SecretKey, error) {
	if len(bytes) != Box512SecretKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly Box512SecretKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBox512SecretKey
	if err := statusError(C.dstu_box512_secretkey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &Box512SecretKey{ptr: out}, nil
}

// Bytes copies out this key's big-endian Box512SecretKeyBytes-byte scalar encoding. The caller is
// responsible for wiping the returned slice once done (see Memzero) - this copies secret material
// into a Go-owned buffer the wrapped native key's own zeroize-on-drop cannot reach.
func (k *Box512SecretKey) Bytes() []byte {
	out := make([]byte, Box512SecretKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box512_secretkey_bytes(k.ptr, outPtr)
	return out
}

// PublicKey derives the public key for this secret key - safe to share/publish.
func (k *Box512SecretKey) PublicKey() *Box512PublicKey {
	return &Box512PublicKey{ptr: C.dstu_box512_secretkey_public_key(k.ptr)}
}

// Open decrypts sealed as produced by Box512PublicKey.Seal. Returns a *CryptoError if
// authentication fails (wrong key, or any tampered wire segment - deliberately not distinguished
// further, see dstu_core::crypto_box512::OpenError's own doc comment) or sealed is too short to be
// valid.
func (k *Box512SecretKey) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < Box512SealOverhead {
		return nil, &CryptoError{"input is shorter than the minimum valid length for this construction"}
	}
	outLen := len(sealed) - Box512SealOverhead
	plaintextOut := make([]byte, outLen)
	sealedPtr, sealedLen := cBytes(sealed)
	ptPtr, ptCap := cBytes(plaintextOut)
	var ptLen C.size_t
	if err := statusError(C.dstu_box512_open(k.ptr, sealedPtr, sealedLen, ptPtr, ptCap, &ptLen)); err != nil {
		return nil, err
	}
	return plaintextOut[:ptLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *Box512SecretKey) Close() error {
	if k.ptr != nil {
		C.dstu_box512_secretkey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}

// Box512PublicKey is a crypto_box512 public key - a curve point's x-coordinate only, see
// dstu_core::crypto_box512's own module doc for why this compression is safe.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type Box512PublicKey struct {
	ptr *C.DstuBox512PublicKey
}

// Box512PublicKeyFromBytes builds a public key from its compressed Box512PublicKeyBytes-byte
// x-coordinate encoding. Returns a *ArgumentError if it isn't a valid field element, or doesn't
// reconstruct to a point inside the base point's own prime-order subgroup.
func Box512PublicKeyFromBytes(bytes []byte) (*Box512PublicKey, error) {
	if len(bytes) != Box512PublicKeyBytes {
		return nil, &ArgumentError{"bytes must be exactly Box512PublicKeyBytes bytes"}
	}
	ptr, _ := cBytes(bytes)
	var out *C.DstuBox512PublicKey
	if err := statusError(C.dstu_box512_publickey_from_bytes(ptr, &out)); err != nil {
		return nil, err
	}
	return &Box512PublicKey{ptr: out}, nil
}

// Bytes copies out this key's Box512PublicKeyBytes-byte encoding - not secret, no wiping needed
// afterward.
func (k *Box512PublicKey) Bytes() []byte {
	out := make([]byte, Box512PublicKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_box512_publickey_bytes(k.ptr, outPtr)
	return out
}

// Seal encrypts message (any length) to the holder of this public key, drawing a fresh random
// seed and ephemeral key internally.
func (k *Box512PublicKey) Seal(message []byte) ([]byte, error) {
	outLen := len(message) + Box512SealOverhead
	sealedOut := make([]byte, outLen)
	msgPtr, msgLen := cBytes(message)
	sealedPtr, sealedCap := cBytes(sealedOut)
	var sealedLen C.size_t
	if err := statusError(C.dstu_box512_seal(k.ptr, msgPtr, msgLen, sealedPtr, sealedCap, &sealedLen)); err != nil {
		return nil, err
	}
	return sealedOut[:sealedLen], nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *Box512PublicKey) Close() error {
	if k.ptr != nil {
		C.dstu_box512_publickey_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
