package dstu

import (
	"bytes"
	"testing"
)

// Kdf (crypto_kdf) - no official vector exists (D-45). Correctness here means determinism/
// distinctness. Misuse: wrong-length master key/context.

func TestDeriveSubkeyIsDeterministic(t *testing.T) {
	key, _ := GenerateKdfMasterKey()
	defer key.Close()
	context := []byte("encrypt_")
	a, err := key.DeriveSubkey(0, context)
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.DeriveSubkey(0, context)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("expected the same subkey twice")
	}
}

func TestDifferentSubkeyIDGivesDifferentSubkey(t *testing.T) {
	key, _ := GenerateKdfMasterKey()
	defer key.Close()
	context := []byte("context1")
	a, _ := key.DeriveSubkey(0, context)
	b, _ := key.DeriveSubkey(1, context)
	if bytes.Equal(a, b) {
		t.Fatal("expected different subkeys")
	}
}

func TestDifferentContextGivesDifferentSubkey(t *testing.T) {
	key, _ := GenerateKdfMasterKey()
	defer key.Close()
	a, _ := key.DeriveSubkey(0, []byte("context1"))
	b, _ := key.DeriveSubkey(0, []byte("context2"))
	if bytes.Equal(a, b) {
		t.Fatal("expected different subkeys")
	}
}

func TestKdfWrongLengthMasterKeyIsRejected(t *testing.T) {
	if _, err := KdfMasterKeyFromBytes(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestKdfWrongLengthContextIsRejected(t *testing.T) {
	key, _ := GenerateKdfMasterKey()
	defer key.Close()
	if _, err := key.DeriveSubkey(0, []byte("short")); err == nil {
		t.Fatal("expected an error")
	}
}
