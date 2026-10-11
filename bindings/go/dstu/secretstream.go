package dstu

// #include "dstu_core.h"
import "C"

import (
	"io"
)

// SecretstreamChunkBytes is the plaintext chunk size uacrypt encrypt's own wire format frames at.
const SecretstreamChunkBytes = 8192

// SecretstreamFormatVersion is the first byte of every stream file. It matches dstu-core's
// crypto_secretstream::FORMAT_VERSION (D-208); the shared vectors pin it.
const SecretstreamFormatVersion = 2

// SecretstreamKey is a genuinely chunked/streaming AEAD master key (crypto_secretstream).
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free.
type SecretstreamKey struct {
	ptr *C.DstuSecretstreamKey
}

// GenerateSecretstreamKey generates a fresh key from the OS CSPRNG.
func GenerateSecretstreamKey() (*SecretstreamKey, error) {
	var out *C.DstuSecretstreamKey
	if err := statusError(C.dstu_secretstream_key_generate(&out)); err != nil {
		return nil, err
	}
	return &SecretstreamKey{ptr: out}, nil
}

// SecretstreamKeyFromBytes builds a key from exactly SecretstreamKeyBytes bytes.
func SecretstreamKeyFromBytes(key []byte) (*SecretstreamKey, error) {
	if len(key) != SecretstreamKeyBytes {
		return nil, &ArgumentError{"key must be exactly SecretstreamKeyBytes bytes"}
	}
	ptr, _ := cBytes(key)
	return &SecretstreamKey{ptr: C.dstu_secretstream_key_from_bytes(ptr)}, nil
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
	}
	return nil
}

// SecretStreamEncryptWriter encrypts writes into uacrypt encrypt's own wire format: a version byte
// and a 32-byte header, then tag(1) || len_u32_le(4) || ciphertext || authTag(16) records. Every
// record but the Final one carries exactly SecretstreamChunkBytes bytes (part of the format since
// D-208). The framing is dstu-core's stream-file codec (T-284) through the C ABI; this type only
// buffers and writes.
//
// Deliberately does not flush a Final chunk from Close - unlike a typical io.WriteCloser's
// close-flushes convention. Call Complete explicitly once all plaintext has been written; a
// writer closed without it is deliberately left without a Final chunk, so a reader fails closed
// on it instead of accepting a truncated stream as complete (D-65, and the concrete D-118 pitfall
// found building bindings/python's own wrapper - Go's defer has no exception-type parameter
// either, so Close can't tell success from an error path the way Python's __exit__ can).
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free (and here, the only thing that closes inner too).
type SecretStreamEncryptWriter struct {
	inner       io.Writer
	innerCloser io.Closer
	enc         *C.DstuFileEncryptor
	buffer      [SecretstreamChunkBytes]byte
	bufferLen   int
	record      [secretstreamMaxRecordBytes]byte
	completed   bool
}

// The C ABI's DSTU_SECRETSTREAM_FILE_PREFIX_BYTES / DSTU_SECRETSTREAM_MAX_RECORD_BYTES.
const (
	secretstreamFilePrefixBytes = 33
	secretstreamMaxRecordBytes  = 8213
)

// NewSecretStreamEncryptWriter starts a new stream under key, writing the version byte and header
// to inner immediately. If inner implements io.Closer, Close closes it too unless leaveOpen is
// true.
func NewSecretStreamEncryptWriter(inner io.Writer, key *SecretstreamKey, leaveOpen bool) (*SecretStreamEncryptWriter, error) {
	prefix := make([]byte, secretstreamFilePrefixBytes)
	prefixPtr, _ := cBytes(prefix)
	var enc *C.DstuFileEncryptor
	if err := statusError(C.dstu_secretstream_file_encryptor_new(key.ptr, prefixPtr, &enc)); err != nil {
		return nil, err
	}
	if _, err := inner.Write(prefix); err != nil {
		C.dstu_secretstream_file_encryptor_free(enc)
		return nil, err
	}
	w := &SecretStreamEncryptWriter{inner: inner, enc: enc}
	if closer, ok := inner.(io.Closer); ok && !leaveOpen {
		w.innerCloser = closer
	}
	return w, nil
}

// Write buffers p, sealing every full SecretstreamChunkBytes chunk that is certain not to be the
// last one; the last (even a full one) waits for Complete. Full chunks are sealed straight from p.
func (w *SecretStreamEncryptWriter) Write(p []byte) (int, error) {
	if w.completed {
		return 0, &ArgumentError{"this writer has already been Complete()d"}
	}
	total := len(p)
	if w.bufferLen+len(p) <= SecretstreamChunkBytes {
		w.bufferLen += copy(w.buffer[w.bufferLen:], p)
		return total, nil
	}
	if w.bufferLen > 0 {
		taken := copy(w.buffer[w.bufferLen:], p)
		p = p[taken:]
		if err := w.sealChunk(w.buffer[:]); err != nil {
			return total - len(p), err
		}
		w.bufferLen = 0
	}
	for len(p) > SecretstreamChunkBytes {
		if err := w.sealChunk(p[:SecretstreamChunkBytes]); err != nil {
			return total - len(p), err
		}
		p = p[SecretstreamChunkBytes:]
	}
	w.bufferLen = copy(w.buffer[:], p)
	return total, nil
}

// Complete writes all buffered plaintext as the Final record and marks this writer complete. Must
// be called once, on the success path, before Close - see the type doc comment for why Close
// itself never does this.
func (w *SecretStreamEncryptWriter) Complete() error {
	if w.completed {
		return nil
	}
	lastPtr, lastLen := cBytes(w.buffer[:w.bufferLen])
	recordPtr, recordCap := cBytes(w.record[:])
	var recordLen C.size_t
	if err := statusError(C.dstu_secretstream_file_encryptor_seal_final(w.enc, lastPtr, lastLen, recordPtr, recordCap, &recordLen)); err != nil {
		return err
	}
	if _, err := w.inner.Write(w.record[:recordLen]); err != nil {
		return err
	}
	w.bufferLen = 0
	w.completed = true
	return nil
}

func (w *SecretStreamEncryptWriter) sealChunk(chunk []byte) error {
	chunkPtr, chunkLen := cBytes(chunk)
	recordPtr, recordCap := cBytes(w.record[:])
	if err := statusError(C.dstu_secretstream_file_encryptor_seal_chunk(w.enc, chunkPtr, chunkLen, recordPtr, recordCap)); err != nil {
		return err
	}
	_, err := w.inner.Write(w.record[:])
	return err
}

// Close releases the underlying native state and, unless leaveOpen was set, closes inner. Safe
// to call more than once. Never emits a Final chunk - see the type doc comment.
func (w *SecretStreamEncryptWriter) Close() error {
	if w.enc != nil {
		C.dstu_secretstream_file_encryptor_free(w.enc)
		w.enc = nil
	}
	if w.innerCloser != nil {
		closer := w.innerCloser
		w.innerCloser = nil
		return closer.Close()
	}
	return nil
}

// SecretStreamDecryptReader decrypts a read side produced by SecretStreamEncryptWriter or
// uacrypt encrypt. Every check - the untrusted length field, the 8 KiB rule, truncation, trailing
// bytes after the Final chunk - is dstu-core's stream-file codec (T-284); this type only reads,
// and reports the codec's own message. The Final chunk is returned only once the input is known
// to end right after it, so a stream with trailing data never yields its last chunk.
//
// No runtime.SetFinalizer backstop - see AuthKey's own doc comment for why: Close() is the only
// way to free (and here, the only thing that closes inner too).
type SecretStreamDecryptReader struct {
	inner       io.Reader
	innerCloser io.Closer
	dec         *C.DstuFileDecryptor
	plaintext   [SecretstreamChunkBytes]byte
	pendingPos  int
	pendingLen  int
	done        bool
}

// NewSecretStreamDecryptReader reads the version byte and the 32-byte header from inner
// immediately. If inner implements io.Closer, Close closes it too unless leaveOpen is true.
func NewSecretStreamDecryptReader(inner io.Reader, key *SecretstreamKey, leaveOpen bool) (*SecretStreamDecryptReader, error) {
	r := &SecretStreamDecryptReader{inner: inner, dec: C.dstu_secretstream_file_decryptor_new(key.ptr)}
	for i := 0; i < 2; i++ {
		if _, err := r.step(); err != nil {
			C.dstu_secretstream_file_decryptor_free(r.dec)
			return nil, err
		}
	}
	if closer, ok := inner.(io.Closer); ok && !leaveOpen {
		r.innerCloser = closer
	}
	return r, nil
}

// Read decrypts and copies plaintext into p, feeding records from inner as needed. Loops past a
// read that released no plaintext rather than returning (0, nil) - io.Reader's contract
// discourages a no-data, no-error return.
func (r *SecretStreamDecryptReader) Read(p []byte) (int, error) {
	for r.pendingPos == r.pendingLen {
		if r.done {
			return 0, io.EOF
		}
		n, err := r.step()
		if err != nil {
			return 0, err
		}
		r.pendingLen = n
		r.pendingPos = 0
	}
	n := copy(p, r.plaintext[r.pendingPos:r.pendingLen])
	r.pendingPos += n
	return n, nil
}

// step feeds the codec one next_len read and returns how many plaintext bytes that released into
// r.plaintext (at end of input, the Final chunk's).
func (r *SecretStreamDecryptReader) step() (int, error) {
	want := int(C.dstu_secretstream_file_decryptor_next_len(r.dec))
	data := make([]byte, want)
	got, err := io.ReadFull(r.inner, data)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return 0, err
	}
	outPtr, outCap := cBytes(r.plaintext[:])
	var n C.size_t
	var status C.DstuStatus
	if got < want {
		r.done = true
		status = C.dstu_secretstream_file_decryptor_finish(r.dec, outPtr, outCap, &n)
	} else {
		dataPtr, dataLen := cBytes(data)
		status = C.dstu_secretstream_file_decryptor_feed(r.dec, dataPtr, dataLen, outPtr, outCap, &n)
	}
	if status != C.DSTU_OK {
		if msg := C.dstu_secretstream_file_decryptor_last_error(r.dec); msg != nil {
			return 0, &CryptoError{C.GoString(msg)}
		}
		return 0, statusError(status)
	}
	return int(n), nil
}

// Close releases the underlying native state and, unless leaveOpen was set, closes inner. Safe
// to call more than once.
func (r *SecretStreamDecryptReader) Close() error {
	if r.dec != nil {
		C.dstu_secretstream_file_decryptor_free(r.dec)
		r.dec = nil
	}
	if r.innerCloser != nil {
		closer := r.innerCloser
		r.innerCloser = nil
		return closer.Close()
	}
	return nil
}
