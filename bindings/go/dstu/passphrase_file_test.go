package dstu

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Passphrase files (D-219, moved into the core by T-269/D-240): NewPassphraseEncryptWriter/
// NewPassphraseDecryptReader, the same bytes uacrypt encrypt --passphrase-file writes. Argon2 is
// 256 MiB, t=3 per run, so only the shared-vector test and the uacrypt interop run it; every
// header refusal stops before Argon2. Mirrors bindings/python/tests/test_passphrase_file.py; the
// C ABI reports statuses, not the core's own messages, so the messages checked are this binding's.

type passphraseCase struct {
	Name          string `json:"name"`
	Expect        string `json:"expect"`
	Argon2        bool   `json:"argon2"`
	PassphraseHex string `json:"passphrase_hex"`
	PlaintextLen  int    `json:"plaintext_len"`
	SealedHex     string `json:"sealed_hex"`
}

func passphraseCases(t *testing.T, argon2 bool) []passphraseCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "crates", "dstu-core", "tests", "vectors", "pwhash", "passphrase_file.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []passphraseCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var out []passphraseCase
	for _, c := range v.Cases {
		if c.Argon2 == argon2 {
			out = append(out, c)
		}
	}
	return out
}

func openPassphraseFile(passphrase, data []byte) ([]byte, error) {
	r, err := NewPassphraseDecryptReader(bytes.NewReader(data), passphrase, true)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func TestPassphraseFileHeaderVectorsAreRefusedBeforeArgon2(t *testing.T) {
	messages := map[string]string{
		"not_passphrase_file": "unsupported format version",
		"unsupported_format":  "unsupported format version",
		"unsupported_params":  "Argon2 parameters",
		"truncated":           "too short",
	}
	refused := passphraseCases(t, false)
	if len(refused) != 6 {
		t.Fatalf("got %d header cases, want 6", len(refused))
	}
	for _, c := range refused {
		_, err := openPassphraseFile(mustHex(t, c.PassphraseHex), mustHex(t, c.SealedHex))
		if err == nil || !strings.Contains(err.Error(), messages[c.Expect]) {
			t.Fatalf("%s: %v, want %q", c.Name, err, messages[c.Expect])
		}
	}
}

func TestPassphraseFilesWrittenByUacrypt060GiveTheirExpectedOutcome(t *testing.T) {
	argon2 := passphraseCases(t, true)
	if len(argon2) != 4 {
		t.Fatalf("got %d Argon2 cases, want 4", len(argon2))
	}
	var cryptoErr *CryptoError
	for _, c := range argon2 {
		got, err := openPassphraseFile(mustHex(t, c.PassphraseHex), mustHex(t, c.SealedHex))
		if c.Expect == "ok" {
			if err != nil || !bytes.Equal(got, pattern(c.PlaintextLen)) {
				t.Fatalf("%s: %v", c.Name, err)
			}
		} else if !errors.As(err, &cryptoErr) {
			t.Fatalf("%s: %v, want *CryptoError", c.Name, err)
		}
	}
}

func TestPassphraseFileRefusesAnEmptyPassphraseOnBothSides(t *testing.T) {
	var argErr *ArgumentError
	if _, err := NewPassphraseEncryptWriter(&bytes.Buffer{}, nil, true); !errors.As(err, &argErr) {
		t.Fatalf("seal: %v, want *ArgumentError", err)
	}
	sealed := mustHex(t, passphraseCases(t, true)[0].SealedHex)
	if _, err := openPassphraseFile(nil, sealed); !errors.As(err, &argErr) {
		t.Fatalf("open: %v, want *ArgumentError", err)
	}
}

func TestPassphraseFileRefusesAKeyEncryptedStream(t *testing.T) {
	key, _ := GenerateSecretstreamKey()
	defer key.Close()
	var buf bytes.Buffer
	w, err := NewSecretStreamEncryptWriter(&buf, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var cryptoErr *CryptoError
	if _, err := openPassphraseFile([]byte("pw"), buf.Bytes()); !errors.As(err, &cryptoErr) {
		t.Fatalf("%v, want *CryptoError", err)
	}
}

func TestPassphraseFileInteropWithUacrypt(t *testing.T) {
	uacrypt := findUacrypt(t)
	if uacrypt == "" {
		t.Skip("uacrypt binary not built (cargo build -p uacrypt)")
	}
	dir := t.TempDir()
	message := pattern(8*1024 + 9)
	passphrase := []byte("спільний пароль")
	pw := filepath.Join(dir, "pw.txt")
	if err := os.WriteFile(pw, passphrase, 0o600); err != nil {
		t.Fatal(err)
	}

	var ours bytes.Buffer
	w, err := NewPassphraseEncryptWriter(&ours, passphrase, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(message); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	w.Close()
	oursPath := filepath.Join(dir, "ours.uac")
	if err := os.WriteFile(oursPath, ours.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	back := filepath.Join(dir, "ours.back")
	runUacrypt(t, uacrypt, "decrypt", "--passphrase-file", pw, "--in", oursPath, "--out", back)
	if got, err := os.ReadFile(back); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("uacrypt decrypt of a Go passphrase file: %v", err)
	}

	plain := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(plain, message, 0o600); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(dir, "theirs.uac")
	runUacrypt(t, uacrypt, "encrypt", "--passphrase-file", pw, "--in", plain, "--out", theirs)
	data, err := os.ReadFile(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := openPassphraseFile(passphrase, data); err != nil || !bytes.Equal(got, message) {
		t.Fatalf("Go open of a uacrypt passphrase file: %v", err)
	}
}
