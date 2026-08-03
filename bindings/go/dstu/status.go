package dstu

// #include "dstu_core.h"
import "C"

import "fmt"

// CryptoError is a genuine crypto-operation/data-integrity failure: wrong key, tampered
// ciphertext/tag/nonce/header, an incomplete secretstream (no Final chunk seen), or Pwhash's
// internal Argon2 failure. Distinct from ArgumentError, which covers a caller-supplied value
// that is well-formed Go but invalid crypto input - mirrors bindings/dotnet's own
// DstuException/ArgumentException split (cross-language style guide principle 4).
type CryptoError struct{ msg string }

func (e *CryptoError) Error() string { return e.msg }

// ArgumentError covers a caller-input mistake this wrapper can check before ever calling into
// native code (wrong key/tag/context length, nil slice where one is required).
type ArgumentError struct{ msg string }

func (e *ArgumentError) Error() string { return e.msg }

// InternalError can only happen if this wrapper itself computed a buffer size or handle wrong -
// not a public failure mode a caller is expected to handle.
type InternalError struct{ status C.DstuStatus }

func (e *InternalError) Error() string {
	return fmt.Sprintf("internal error in the DstuCore Go binding (status %d) - please report this", int(e.status))
}

// statusError maps a raw DstuStatus to the typed error a caller should actually see.
func statusError(status C.DstuStatus) error {
	switch status {
	case C.DSTU_OK:
		return nil
	case C.DSTU_ERR_RANDOM:
		return &CryptoError{"OS CSPRNG failure while generating random data"}
	case C.DSTU_ERR_TAG_MISMATCH:
		return &CryptoError{"authentication failed: wrong key, or tampered ciphertext/tag/nonce/header"}
	case C.DSTU_ERR_TRUNCATED:
		return &CryptoError{"input is shorter than the minimum valid length for this construction"}
	case C.DSTU_ERR_UNKNOWN_TAG:
		return &CryptoError{"secretstream chunk has an invalid tag byte - the stream is corrupted or truncated"}
	case C.DSTU_ERR_FINALIZED:
		return &CryptoError{"this secretstream state has already emitted/consumed a Final chunk"}
	case C.DSTU_ERR_SELFTEST_FAILED:
		return &CryptoError{"dstu_selftest: a known-answer self-check failed against the compiled build"}
	case C.DSTU_ERR_HASH_ERROR:
		return &CryptoError{"crypto_pwhash: internal Argon2/PHC-encoding failure"}
	case C.DSTU_ERR_INVALID_KEY:
		return &ArgumentError{"invalid key material (e.g. a DSTU 4145 scalar that is zero or >= the curve order)"}
	default: // ErrBufferTooSmall, ErrNullPointer, ErrInvalidLength, ErrPanic
		return &InternalError{status}
	}
}
