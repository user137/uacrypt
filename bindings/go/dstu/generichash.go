package dstu

// #include "dstu_core.h"
import "C"

// GenericHash256 computes the one-shot Kupyna-256 digest of message.
func GenericHash256(message []byte) []byte {
	out := make([]byte, GenericHash256Bytes)
	msgPtr, msgLen := cBytes(message)
	outPtr, _ := cBytes(out)
	C.dstu_generichash_256(msgPtr, msgLen, outPtr)
	return out
}

// GenericHash512 computes the one-shot Kupyna-512 digest of message.
func GenericHash512(message []byte) []byte {
	out := make([]byte, GenericHash512Bytes)
	msgPtr, msgLen := cBytes(message)
	outPtr, _ := cBytes(out)
	C.dstu_generichash_512(msgPtr, msgLen, outPtr)
	return out
}

// Kupyna256Hasher is an incremental Kupyna-256 hasher for data too large to hold in memory at
// once. For a one-shot digest, use GenericHash256.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type Kupyna256Hasher struct {
	ptr       *C.DstuKupyna256Hasher
	finalized bool
}

// NewKupyna256Hasher creates a new streaming hasher.
func NewKupyna256Hasher() *Kupyna256Hasher {
	return &Kupyna256Hasher{ptr: C.dstu_kupyna256_hasher_new()}
}

// Update feeds data into the hasher.
func (h *Kupyna256Hasher) Update(data []byte) error {
	if h.finalized {
		return &ArgumentError{"this hasher has already been finalized"}
	}
	ptr, length := cBytes(data)
	C.dstu_kupyna256_hasher_update(h.ptr, ptr, length)
	return nil
}

// Finalize consumes the hasher's accumulated state into a GenericHash256Bytes-byte digest. May
// only be called once.
func (h *Kupyna256Hasher) Finalize() ([]byte, error) {
	if h.finalized {
		return nil, &ArgumentError{"this hasher has already been finalized"}
	}
	out := make([]byte, GenericHash256Bytes)
	outPtr, _ := cBytes(out)
	if err := statusError(C.dstu_kupyna256_hasher_finalize(h.ptr, outPtr)); err != nil {
		return nil, err
	}
	h.finalized = true
	return out, nil
}

// Close releases the underlying native hasher. Safe to call more than once, finalized or not.
func (h *Kupyna256Hasher) Close() error {
	if h.ptr != nil {
		C.dstu_kupyna256_hasher_free(h.ptr)
		h.ptr = nil
	}
	return nil
}

// Kupyna512Hasher is an incremental Kupyna-512 hasher. Same shape as Kupyna256Hasher.
type Kupyna512Hasher struct {
	ptr       *C.DstuKupyna512Hasher
	finalized bool
}

// NewKupyna512Hasher creates a new streaming hasher.
func NewKupyna512Hasher() *Kupyna512Hasher {
	return &Kupyna512Hasher{ptr: C.dstu_kupyna512_hasher_new()}
}

// Update feeds data into the hasher.
func (h *Kupyna512Hasher) Update(data []byte) error {
	if h.finalized {
		return &ArgumentError{"this hasher has already been finalized"}
	}
	ptr, length := cBytes(data)
	C.dstu_kupyna512_hasher_update(h.ptr, ptr, length)
	return nil
}

// Finalize consumes the hasher's accumulated state into a GenericHash512Bytes-byte digest. May
// only be called once.
func (h *Kupyna512Hasher) Finalize() ([]byte, error) {
	if h.finalized {
		return nil, &ArgumentError{"this hasher has already been finalized"}
	}
	out := make([]byte, GenericHash512Bytes)
	outPtr, _ := cBytes(out)
	if err := statusError(C.dstu_kupyna512_hasher_finalize(h.ptr, outPtr)); err != nil {
		return nil, err
	}
	h.finalized = true
	return out, nil
}

// Close releases the underlying native hasher. Safe to call more than once, finalized or not.
func (h *Kupyna512Hasher) Close() error {
	if h.ptr != nil {
		C.dstu_kupyna512_hasher_free(h.ptr)
		h.ptr = nil
	}
	return nil
}
