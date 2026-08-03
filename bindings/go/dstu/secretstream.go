package dstu

// #include "dstu_core.h"
import "C"

import (
	"encoding/binary"
	"io"
	"runtime"
)

// SecretstreamChunkBytes is the plaintext chunk size uacrypt encrypt's own wire format frames at.
const SecretstreamChunkBytes = 8192

// SecretstreamKey is a genuinely chunked/streaming AEAD master key (crypto_secretstream).
type SecretstreamKey struct {
	ptr *C.DstuSecretstreamKey
}

// GenerateSecretstreamKey generates a fresh key from the OS CSPRNG.
func GenerateSecretstreamKey() (*SecretstreamKey, error) {
	var out *C.DstuSecretstreamKey
	if err := statusError(C.dstu_secretstream_key_generate(&out)); err != nil {
		return nil, err
	}
	return newSecretstreamKey(out), nil
}

// SecretstreamKeyFromBytes builds a key from exactly SecretstreamKeyBytes bytes.
func SecretstreamKeyFromBytes(key []byte) (*SecretstreamKey, error) {
	if len(key) != SecretstreamKeyBytes {
		return nil, &ArgumentError{"key must be exactly SecretstreamKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return newSecretstreamKey(C.dstu_secretstream_key_from_bytes(ptr)), nil
}

func newSecretstreamKey(ptr *C.DstuSecretstreamKey) *SecretstreamKey {
	k := &SecretstreamKey{ptr: ptr}
	runtime.SetFinalizer(k, (*SecretstreamKey).Close)
	return k
}

// Bytes copies out this key's raw SecretstreamKeyBytes-byte encoding.
func (k *SecretstreamKey) Bytes() []byte {
	out := make([]byte, SecretstreamKeyBytes)
	outPtr, _ := cBytes(out)
	C.dstu_secretstream_key_bytes(k.ptr, outPtr)
	return out
}

// Close releases the underlying native key. Safe to call more than once.
func (k *SecretstreamKey) Close() error {
	if k.ptr != nil {
		C.dstu_secretstream_key_free(k.ptr)
		k.ptr = nil
		runtime.SetFinalizer(k, nil)
	}
	return nil
}

// SecretStreamEncryptWriter encrypts writes into uacrypt encrypt's own wire format: a 32-byte
// header, then tag(1) || len_u32_le(4) || ciphertext || authTag(16) records framed at
// SecretstreamChunkBytes-byte plaintext boundaries.
//
// Deliberately does not flush a Final chunk from Close - unlike a typical io.WriteCloser's
// close-flushes convention. Call Complete explicitly once all plaintext has been written; a
// writer closed without it is deliberately left without a Final chunk, so a reader fails closed
// on it instead of accepting a truncated stream as complete (D-65, and the concrete D-118 pitfall
// found building bindings/python's own wrapper - Go's defer has no exception-type parameter
// either, so Close can't tell success from an error path the way Python's __exit__ can).
type SecretStreamEncryptWriter struct {
	inner       io.Writer
	innerCloser io.Closer
	state       *C.DstuPushState
	buffer      [SecretstreamChunkBytes]byte
	bufferLen   int
	pending     []byte
	completed   bool
}

// NewSecretStreamEncryptWriter starts a new stream under key, writing the header to inner
// immediately. If inner implements io.Closer, Close closes it too unless leaveOpen is true.
func NewSecretStreamEncryptWriter(inner io.Writer, key *SecretstreamKey, leaveOpen bool) (*SecretStreamEncryptWriter, error) {
	header := make([]byte, SecretstreamHeaderBytes)
	headerPtr, _ := cBytes(header)
	var state *C.DstuPushState
	if err := statusError(C.dstu_secretstream_push_init(key.ptr, &state, headerPtr)); err != nil {
		return nil, err
	}
	if _, err := inner.Write(header); err != nil {
		C.dstu_secretstream_push_free(state)
		return nil, err
	}
	w := &SecretStreamEncryptWriter{inner: inner, state: state}
	if closer, ok := inner.(io.Closer); ok && !leaveOpen {
		w.innerCloser = closer
	}
	runtime.SetFinalizer(w, (*SecretStreamEncryptWriter).Close)
	return w, nil
}

// Write buffers p, encrypting and emitting a Message chunk each time SecretstreamChunkBytes of
// plaintext accumulate.
func (w *SecretStreamEncryptWriter) Write(p []byte) (int, error) {
	if w.completed {
		return 0, &ArgumentError{"this writer has already been Complete()d"}
	}
	written := 0
	for len(p) > 0 {
		take := copy(w.buffer[w.bufferLen:], p)
		w.bufferLen += take
		p = p[take:]
		written += take
		if w.bufferLen == len(w.buffer) {
			if err := w.flushPendingAsMessage(); err != nil {
				return written, err
			}
			w.pending = append([]byte(nil), w.buffer[:]...)
			w.bufferLen = 0
		}
	}
	return written, nil
}

// Complete flushes all buffered plaintext as a Final chunk and marks this writer complete. Must
// be called once, on the success path, before Close - see the type doc comment for why Close
// itself never does this.
func (w *SecretStreamEncryptWriter) Complete() error {
	if w.completed {
		return nil
	}
	switch {
	case w.bufferLen > 0:
		if err := w.flushPendingAsMessage(); err != nil {
			return err
		}
		if err := w.writeChunk(TagFinal, w.buffer[:w.bufferLen]); err != nil {
			return err
		}
	case w.pending != nil:
		pending := w.pending
		w.pending = nil
		if err := w.writeChunk(TagFinal, pending); err != nil {
			return err
		}
	default:
		if err := w.writeChunk(TagFinal, nil); err != nil {
			return err
		}
	}
	w.completed = true
	return nil
}

func (w *SecretStreamEncryptWriter) flushPendingAsMessage() error {
	if w.pending == nil {
		return nil
	}
	pending := w.pending
	w.pending = nil
	return w.writeChunk(TagMessage, pending)
}

func (w *SecretStreamEncryptWriter) writeChunk(tag SecretstreamTag, plaintext []byte) error {
	ciphertext := make([]byte, len(plaintext))
	tagOut := make([]byte, SecretstreamTagBytes)
	ptPtr, ptLen := cBytes(plaintext)
	ctPtr, ctLen := cBytes(ciphertext)
	tagOutPtr, _ := cBytes(tagOut)
	if err := statusError(C.dstu_secretstream_push(w.state, C.DstuTag(tag), ptPtr, ptLen, ctPtr, ctLen, tagOutPtr)); err != nil {
		return err
	}

	var header [5]byte
	header[0] = byte(tag)
	binary.LittleEndian.PutUint32(header[1:], uint32(len(plaintext)))
	if _, err := w.inner.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.inner.Write(ciphertext); err != nil {
		return err
	}
	_, err := w.inner.Write(tagOut)
	return err
}

// Close releases the underlying native state and, unless leaveOpen was set, closes inner. Safe
// to call more than once. Never emits a Final chunk - see the type doc comment.
func (w *SecretStreamEncryptWriter) Close() error {
	if w.state != nil {
		C.dstu_secretstream_push_free(w.state)
		w.state = nil
		runtime.SetFinalizer(w, nil)
	}
	if w.innerCloser != nil {
		closer := w.innerCloser
		w.innerCloser = nil
		return closer.Close()
	}
	return nil
}

// SecretStreamDecryptReader decrypts a read side produced by SecretStreamEncryptWriter or
// uacrypt encrypt. Bounds every untrusted length-prefixed chunk-length field against
// SecretstreamChunkBytes before using it to size a read, and rejects trailing bytes after the
// Final chunk - both checks the wire format's own framing does not provide for free (D-118's
// second pitfall; mirrors uacrypt's own CliError::SecretstreamChunkTooLarge/
// SecretstreamTrailingData).
type SecretStreamDecryptReader struct {
	inner       io.Reader
	innerCloser io.Closer
	state       *C.DstuPullState
	pending     []byte
	pendingPos  int
	finalized   bool
}

// NewSecretStreamDecryptReader reads the 32-byte header from inner immediately and re-derives the
// stream's initial subkey. If inner implements io.Closer, Close closes it too unless leaveOpen is
// true.
func NewSecretStreamDecryptReader(inner io.Reader, key *SecretstreamKey, leaveOpen bool) (*SecretStreamDecryptReader, error) {
	header, err := readExactly(inner, SecretstreamHeaderBytes)
	if err != nil {
		return nil, err
	}
	headerPtr, _ := cBytes(header)
	state := C.dstu_secretstream_pull_init(key.ptr, headerPtr)
	r := &SecretStreamDecryptReader{inner: inner, state: state}
	if closer, ok := inner.(io.Closer); ok && !leaveOpen {
		r.innerCloser = closer
	}
	runtime.SetFinalizer(r, (*SecretStreamDecryptReader).Close)
	return r, nil
}

// Read decrypts and copies plaintext into p, pulling and verifying chunks from inner as needed.
func (r *SecretStreamDecryptReader) Read(p []byte) (int, error) {
	if r.pendingPos == len(r.pending) {
		ok, err := r.readNextChunk()
		if err != nil {
			return 0, err
		}
		if !ok {
			if !r.finalized {
				return 0, &CryptoError{"secretstream ended before a Final chunk was seen - the input is truncated"}
			}
			return 0, io.EOF
		}
	}
	n := copy(p, r.pending[r.pendingPos:])
	r.pendingPos += n
	return n, nil
}

func (r *SecretStreamDecryptReader) readNextChunk() (bool, error) {
	tagByte := make([]byte, 1)
	n, err := io.ReadFull(r.inner, tagByte)
	if n == 0 && err != nil {
		return false, nil
	}
	if err != nil {
		return false, &CryptoError{"secretstream ended unexpectedly mid-chunk - the input is truncated"}
	}

	lenBytes, err := readExactly(r.inner, 4)
	if err != nil {
		return false, err
	}
	length := binary.LittleEndian.Uint32(lenBytes)
	if length > SecretstreamChunkBytes {
		return false, &CryptoError{"secretstream chunk length exceeds the maximum SecretstreamChunkBytes - the input is corrupted"}
	}

	ciphertext, err := readExactly(r.inner, int(length))
	if err != nil {
		return false, err
	}
	authTag, err := readExactly(r.inner, SecretstreamTagBytes)
	if err != nil {
		return false, err
	}

	plaintextOut := make([]byte, length)
	ctPtr, ctLen := cBytes(ciphertext)
	authPtr, _ := cBytes(authTag)
	ptPtr, ptLen := cBytes(plaintextOut)
	var outTag C.DstuTag
	if err := statusError(C.dstu_secretstream_pull(r.state, C.uint8_t(tagByte[0]), ctPtr, ctLen, authPtr, ptPtr, ptLen, &outTag)); err != nil {
		return false, err
	}

	r.pending = plaintextOut
	r.pendingPos = 0
	if SecretstreamTag(outTag) == TagFinal {
		r.finalized = true
		var trailing [1]byte
		if n, _ := r.inner.Read(trailing[:]); n != 0 {
			return false, &CryptoError{"secretstream has trailing data after its Final chunk"}
		}
	}
	return true, nil
}

func readExactly(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, &CryptoError{"secretstream ended unexpectedly mid-chunk - the input is truncated"}
	}
	return buf, nil
}

// Close releases the underlying native state and, unless leaveOpen was set, closes inner. Safe
// to call more than once.
func (r *SecretStreamDecryptReader) Close() error {
	if r.state != nil {
		C.dstu_secretstream_pull_free(r.state)
		r.state = nil
		runtime.SetFinalizer(r, nil)
	}
	if r.innerCloser != nil {
		closer := r.innerCloser
		r.innerCloser = nil
		return closer.Close()
	}
	return nil
}
