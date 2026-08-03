package dstu

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// SecretstreamKey/SecretStreamEncryptWriter/SecretStreamDecryptReader (crypto_secretstream) -
// correctness (round trip across chunk-boundary sizes, plus real byte-for-byte interop with
// uacrypt encrypt/decrypt's own wire format), rejection (tamper, oversized chunk, trailing data,
// truncation), misuse (wrong-length key, write-after-Complete).

func TestSecretstreamWrongLengthKeyIsRejected(t *testing.T) {
	if _, err := SecretstreamKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamRoundTripsAcrossChunkBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 100, 8 * 1024, 8*1024 + 1, 8 * 1024 * 3, 8*1024*3 + 777} {
		size := size
		t.Run("", func(t *testing.T) {
			key, err := GenerateSecretstreamKey()
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			plaintext, err := RandomBytes(size)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			w, err := NewSecretStreamEncryptWriter(&buf, key, true)
			if err != nil {
				t.Fatal(err)
			}
			const step = 777
			for i := 0; i < len(plaintext); i += step {
				end := i + step
				if end > len(plaintext) {
					end = len(plaintext)
				}
				if _, err := w.Write(plaintext[i:end]); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Complete(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}

			r, err := NewSecretStreamDecryptReader(&buf, key, true)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round trip mismatch at size %d: got %d bytes, want %d", size, len(got), len(plaintext))
			}
		})
	}
}

func TestSecretstreamInteropWithUacryptCli(t *testing.T) {
	uacrypt := findUacrypt(t)
	if uacrypt == "" {
		t.Skip("uacrypt binary not built (cargo build -p uacrypt)")
	}

	tempDir := t.TempDir()
	key, err := GenerateSecretstreamKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	keyPath := filepath.Join(tempDir, "key.bin")
	if err := os.WriteFile(keyPath, key.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext, err := RandomBytes(8*1024*2 + 555)
	if err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(tempDir, "plain.bin")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	goEncryptedPath := filepath.Join(tempDir, "go_encrypted.bin")
	f, err := os.Create(goEncryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewSecretStreamEncryptWriter(f, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	uacryptDecryptedPath := filepath.Join(tempDir, "uacrypt_decrypted.bin")
	runUacrypt(t, uacrypt, "decrypt", "--key", keyPath, "--in", goEncryptedPath, "--out", uacryptDecryptedPath)
	got, err := os.ReadFile(uacryptDecryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("uacrypt decrypt of the Go-encrypted stream did not match the original plaintext")
	}

	uacryptEncryptedPath := filepath.Join(tempDir, "uacrypt_encrypted.bin")
	runUacrypt(t, uacrypt, "encrypt", "--key", keyPath, "--in", plainPath, "--out", uacryptEncryptedPath)
	uf, err := os.Open(uacryptEncryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewSecretStreamDecryptReader(uf, key, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("Go decrypt of the uacrypt-encrypted stream did not match the original plaintext")
	}
}

func runUacrypt(t *testing.T, uacrypt string, args ...string) {
	t.Helper()
	cmd := exec.Command(uacrypt, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("uacrypt failed: %v: %s", err, stderr.String())
	}
}

func TestSecretstreamTamperedChunkIsRejected(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("secret message")); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	data[len(data)-1] ^= 1 // last byte of the Final chunk's auth tag
	r, err := NewSecretStreamDecryptReader(bytes.NewReader(data), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamTruncatedStreamIsRejected(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}

	truncated := buf.Bytes()[:100]
	r, err := NewSecretStreamDecryptReader(bytes.NewReader(truncated), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamOversizedDeclaredChunkLengthIsRejected(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	malicious := make([]byte, 32+1+4)
	malicious[32] = byte(TagFinal)
	binary.LittleEndian.PutUint32(malicious[33:], 0xFFFFFFFF)
	r, err := NewSecretStreamDecryptReader(bytes.NewReader(malicious), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamTrailingDataAfterFinalIsRejected(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("msg")); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("unexpected trailing bytes")

	r, err := NewSecretStreamDecryptReader(bytes.NewReader(buf.Bytes()), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamNotCallingCompleteLeavesStreamUnfinalized(t *testing.T) {
	// D-118: Close() never emits a Final chunk - Go's defer has no exception-type parameter, same
	// reasoning as bindings/dotnet's Dispose/Complete split, so this holds unconditionally, not
	// just on an error path.
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("chunk one")); err != nil {
		t.Fatal(err)
	}
	// deliberately no Complete() call
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := NewSecretStreamDecryptReader(bytes.NewReader(buf.Bytes()), key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSecretstreamWriteAfterCompleteIsRejected(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("more data")); err == nil {
		t.Fatal("expected an error")
	}
}
