package dstu

// #include "dstu_core.h"
import "C"

// SigningKey257 is a DSTU 4145 m=257 signing key (crypto_sign257, T-199/T-204) - the curve real
// Diia-issued qualified signatures use. Same shape as SigningKey, a distinct type - not
// interchangeable with crypto_sign's m=163. Signing is deterministic (Kupyna-KMAC-derived nonce) -
// no RNG dependency beyond key generation.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type SigningKey257 struct {
	ptr *C.DstuSigningKey257
}

// GenerateSigningKey257 generates a fresh signing key from the OS CSPRNG.
func GenerateSigningKey257() (*SigningKey257, error) {
	var out *C.DstuSigningKey257
	if err := statusError(C.dstu_sign257_key_generate(&out)); err != nil {
		return nil, err
	}
	return &SigningKey257{ptr: out}, nil
}

// SigningKey257FromBytes builds a signing key from a big-endian Sign257PrivateKeyBytes-byte
// scalar d. Returns a *ArgumentError if d is zero or >= the curve order.
func SigningKey257FromBytes(d []byte) (*SigningKey257, error) {
	if len(d) != Sign257PrivateKeyBytes {
		return nil, &ArgumentError{"d must be exactly Sign257PrivateKeyBytes bytes"}
	}
	dPtr, _ := cBytes(d)
	var out *C.DstuSigningKey257
	if err := statusError(C.dstu_sign257_key_from_bytes(dPtr, &out)); err != nil {
		return nil, err
	}
	return &SigningKey257{ptr: out}, nil
}

// Bytes copies out this key's big-endian Sign257PrivateKeyBytes-byte scalar encoding. The caller
// is responsible for wiping the returned slice once done (see Memzero) - this copies secret
// material into a Go-owned buffer the wrapped native key's own zeroize-on-drop cannot reach.
func (k *SigningKey257) Bytes() []byte {
	out := make([]byte, Sign257PrivateKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_sign257_key_bytes(k.ptr, outPtr)
	return out
}

// VerifyingKey derives the public verifying key for this signing key.
func (k *SigningKey257) VerifyingKey() *VerifyingKey257 {
	return &VerifyingKey257{ptr: C.dstu_sign257_verifying_key(k.ptr)}
}

// Sign signs message, hashing it with Kupyna-256 internally.
func (k *SigningKey257) Sign(message []byte) []byte {
	sig := make([]byte, Sign257SignatureBytes)
	msgPtr, msgLen := cBytes(message)
	sigPtr, _ := cBytes(sig)
	C.dstu_sign257(k.ptr, msgPtr, msgLen, sigPtr)
	return sig
}

// SignDigest signs an already-computed Sign257DigestBytes-byte Kupyna-256 digest directly - for a
// message hashed incrementally rather than held whole in memory.
func (k *SigningKey257) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != Sign257DigestBytes {
		return nil, &ArgumentError{"digest must be exactly Sign257DigestBytes bytes"}
	}
	sig := make([]byte, Sign257SignatureBytes)
	digestPtr, _ := cBytes(digest)
	sigPtr, _ := cBytes(sig)
	C.dstu_sign257_digest(k.ptr, digestPtr, sigPtr)
	return sig, nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *SigningKey257) Close() error {
	if k.ptr != nil {
		C.dstu_sign257_key_free(k.ptr)
		k.ptr = nil
	}
	return nil
}

// VerifyingKey257 is a DSTU 4145 m=257 public verifying key. No curve-tag byte at this layer - the
// tag/dispatch mechanism lives at the uacrypt serialization layer only (D-118), the same
// convention the underlying C ABI's own module doc documents.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type VerifyingKey257 struct {
	ptr *C.DstuVerifyingKey257
}

// VerifyingKey257FromBytes builds a verifying key from Sign257PublicKeyBytes bytes of plain
// x || y encoding - no validation that the point is on the curve, matching the wrapped native
// function's own convention.
func VerifyingKey257FromBytes(b []byte) (*VerifyingKey257, error) {
	if len(b) != Sign257PublicKeyBytes {
		return nil, &ArgumentError{"b must be exactly Sign257PublicKeyBytes bytes"}
	}
	ptr, _ := cBytes(b)
	return &VerifyingKey257{ptr: C.dstu_verifying_key257_from_bytes(ptr)}, nil
}

// Bytes copies out this key's plain x || y Sign257PublicKeyBytes-byte encoding (not the DSTU 4145
// standard's own compressed point encoding).
func (k *VerifyingKey257) Bytes() []byte {
	out := make([]byte, Sign257PublicKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_verifying_key257_to_bytes(k.ptr, outPtr)
	return out
}

// Verify verifies sig over message.
func (k *VerifyingKey257) Verify(message, sig []byte) (bool, error) {
	if len(sig) != Sign257SignatureBytes {
		return false, &ArgumentError{"sig must be exactly Sign257SignatureBytes bytes"}
	}
	msgPtr, msgLen := cBytes(message)
	sigPtr, _ := cBytes(sig)
	return bool(C.dstu_verify257(k.ptr, msgPtr, msgLen, sigPtr)), nil
}

// VerifyDigest verifies sig over an already-computed Sign257DigestBytes-byte digest directly.
func (k *VerifyingKey257) VerifyDigest(digest, sig []byte) (bool, error) {
	if len(digest) != Sign257DigestBytes {
		return false, &ArgumentError{"digest must be exactly Sign257DigestBytes bytes"}
	}
	if len(sig) != Sign257SignatureBytes {
		return false, &ArgumentError{"sig must be exactly Sign257SignatureBytes bytes"}
	}
	digestPtr, _ := cBytes(digest)
	sigPtr, _ := cBytes(sig)
	return bool(C.dstu_verify257_digest(k.ptr, digestPtr, sigPtr)), nil
}

// Close releases the underlying native key. Safe to call more than once.
func (k *VerifyingKey257) Close() error {
	if k.ptr != nil {
		C.dstu_verifying_key257_free(k.ptr)
		k.ptr = nil
	}
	return nil
}
