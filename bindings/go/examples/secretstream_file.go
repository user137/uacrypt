package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// crypto_secretstream: encrypt/decrypt a file incrementally, chunk by chunk, via
// SecretStreamEncryptWriter/SecretStreamDecryptReader (D-118). The wire format matches
// uacrypt encrypt/decrypt exactly - a file this writes is decryptable by the uacrypt CLI and
// vice versa.
func runSecretstreamFile() error {
	key, err := dstu.GenerateSecretstreamKey()
	if err != nil {
		return err
	}
	defer key.Close()

	line := []byte("a message spread across more than one 8 KiB chunk\n")
	plaintext := bytes.Repeat(line, 1000)

	tempDir, err := os.MkdirTemp("", "dstu-core-example-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	encryptedPath := filepath.Join(tempDir, "message.enc")
	decryptedPath := filepath.Join(tempDir, "message.dec")

	f, err := os.Create(encryptedPath)
	if err != nil {
		return err
	}
	w, err := dstu.NewSecretStreamEncryptWriter(f, key, false)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return err
	}
	if err := w.Complete(); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	ef, err := os.Open(encryptedPath)
	if err != nil {
		return err
	}
	r, err := dstu.NewSecretStreamDecryptReader(ef, key, false)
	if err != nil {
		return err
	}
	recovered, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return err
	}

	if !bytes.Equal(recovered, plaintext) {
		return fmt.Errorf("round trip failed")
	}

	info, err := os.Stat(encryptedPath)
	if err != nil {
		return err
	}
	fmt.Printf("%d bytes -> %d bytes on disk, round-tripped OK\n", len(plaintext), info.Size())
	return os.WriteFile(decryptedPath, recovered, 0o600)
}
