package dstu

// #include "dstu_core.h"
import "C"

// SigningKey is a DSTU 4145 signing key (crypto_sign). Signing is deterministic
// (Kupyna-KMAC-derived nonce) - no RNG dependency beyond key generation.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type SigningKey struct {
	ptr *C.DstuSigningKey
}

// GenerateSigningKey generates a fresh signing key from the OS CSPRNG.
func GenerateSigningKey() (*SigningKey, error) {
	var out *C.DstuSigningKey
	if err := statusError(C.dstu_sign_key_generate(&out)); err != nil {
		return nil, err
	}
	return &SigningKey{ptr: out}, nil
}

// SigningKeyFromBytes builds a signing key from a big-endian SignPrivateKeyBytes-byte scalar d.
// Returns a *ArgumentError if d is zero or >= the curve order.
func SigningKeyFromBytes(d []byte) (*SigningKey, error) {
	if len(d) != SignPrivateKeyBytes {
		return nil, &ArgumentError{"d must be exactly SignPrivateKeyBytes bytes"}
	}
	dPtr, _ := cBytes(d)
	var out *C.DstuSigningKey
	if err := statusError(C.dstu_sign_key_from_bytes(dPtr, &out)); err != nil {
		return nil, err
	}
	return &SigningKey{ptr: out}, nil
}

// Bytes copies out this key's big-endian SignPrivateKeyBytes-byte scalar encoding. The caller is
// responsible for wiping the returned slice once done (see Memzero) - this copies secret material
// into a Go-owned buffer the wrapped native key's own zeroize-on-drop cannot reach.
func (k *SigningKey) Bytes() []byte {
	out := make([]byte, SignPrivateKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_sign_key_bytes(k.ptr, outPtr)
	return out
}

// VerifyingKey derives the public verifying key for this signing key.
func (k *SigningKey) VerifyingKey() *VerifyingKey {
	return &VerifyingKey{ptr: C.dstu_sign_verifying_key(k.ptr)}
}

// Sign signs message, hashing it with Kupyna-256 internally.
func (k *SigningKey) Sign(message []byte) []byte {
	sig := make([]byte, SignSignatureBytes)
	msgPtr, msgLen := cBytes(message)
	sigPtr, _ := cBytes(sig)
	C.dstu_sign(k.ptr, msgPtr, msgLen, sigPtr)
	return sig
}

// SignDigest signs an already-computed SignDigestBytes-byte Kupyna-256 digest directly - for a
// message hashed incrementally rather than held whole in memory.
func (k *SigningKey) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != SignDigestBytes {
		return nil, &ArgumentError{"digest must be exactly SignDigestBytes bytes"}
	}
	sig := make([]byte, SignSignatureBytes)
	digestPtr, _ := cBytes(digest)
	sigPtr, _ := cBytes(sig)
	C.dstu_sign_digest(k.ptr, digestPtr, sigPtr)
	return sig, nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *SigningKey) Close() error {
	if k.ptr != nil {
		C.dstu_sign_key_free(k.ptr)
		k.ptr = nil
	}
	return nil
}

// VerifyingKey is a DSTU 4145 public verifying key.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type VerifyingKey struct {
	ptr *C.DstuVerifyingKey
}

// VerifyingKeyFromBytes builds a verifying key from SignPublicKeyBytes bytes of plain x || y
// encoding - no validation that the point is on the curve, matching the wrapped native function's
// own convention.
func VerifyingKeyFromBytes(b []byte) (*VerifyingKey, error) {
	if len(b) != SignPublicKeyBytes {
		return nil, &ArgumentError{"b must be exactly SignPublicKeyBytes bytes"}
	}
	ptr, _ := cBytes(b)
	return &VerifyingKey{ptr: C.dstu_verifying_key_from_bytes(ptr)}, nil
}

// Bytes copies out this key's plain x || y SignPublicKeyBytes-byte encoding (not the DSTU 4145
// standard's own compressed point encoding).
func (k *VerifyingKey) Bytes() []byte {
	out := make([]byte, SignPublicKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_verifying_key_to_bytes(k.ptr, outPtr)
	return out
}

// Verify verifies sig over message.
func (k *VerifyingKey) Verify(message, sig []byte) (bool, error) {
	if len(sig) != SignSignatureBytes {
		return false, &ArgumentError{"sig must be exactly SignSignatureBytes bytes"}
	}
	msgPtr, msgLen := cBytes(message)
	sigPtr, _ := cBytes(sig)
	return bool(C.dstu_verify(k.ptr, msgPtr, msgLen, sigPtr)), nil
}

// VerifyDigest verifies sig over an already-computed SignDigestBytes-byte digest directly.
func (k *VerifyingKey) VerifyDigest(digest, sig []byte) (bool, error) {
	if len(digest) != SignDigestBytes {
		return false, &ArgumentError{"digest must be exactly SignDigestBytes bytes"}
	}
	if len(sig) != SignSignatureBytes {
		return false, &ArgumentError{"sig must be exactly SignSignatureBytes bytes"}
	}
	digestPtr, _ := cBytes(digest)
	sigPtr, _ := cBytes(sig)
	return bool(C.dstu_verify_digest(k.ptr, digestPtr, sigPtr)), nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *VerifyingKey) Close() error {
	if k.ptr != nil {
		C.dstu_verifying_key_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
