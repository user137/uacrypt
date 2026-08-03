package dstu

import (
	"bytes"
	"testing"
)

// GenericHash (Kupyna-256/512) - correctness against a real official Kupyna-256 vector loaded
// directly from the same JSON the Rust crate's own tests and Selftest use, plus one-shot/streaming
// agreement. Misuse: finalizing twice.

func TestKupyna256MatchesOfficialVector(t *testing.T) {
	c := loadFirstVectorCase(t, "crates/dstu-core/tests/vectors/kupyna/kupyna-256.json")
	message := mustHex(t, c["message_hex"])
	expected := mustHex(t, c["hash_hex"])
	got := GenericHash256(message)
	if !bytes.Equal(got, expected) {
		t.Fatalf("got %x, want %x", got, expected)
	}
}

func TestStreamingHasherMatchesOneShot256(t *testing.T) {
	whole := GenericHash256([]byte("hello world"))
	h := NewKupyna256Hasher()
	defer h.Close()
	if err := h.Update([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if err := h.Update([]byte("world")); err != nil {
		t.Fatal(err)
	}
	got, err := h.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, whole) {
		t.Fatalf("got %x, want %x", got, whole)
	}
}

func TestStreamingHasherMatchesOneShot512(t *testing.T) {
	whole := GenericHash512([]byte("hello world"))
	h := NewKupyna512Hasher()
	defer h.Close()
	_ = h.Update([]byte("hello "))
	_ = h.Update([]byte("world"))
	got, err := h.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, whole) {
		t.Fatalf("got %x, want %x", got, whole)
	}
}

func TestFinalizeTwiceIsRejected(t *testing.T) {
	h := NewKupyna256Hasher()
	defer h.Close()
	_ = h.Update([]byte("data"))
	if _, err := h.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Finalize(); err == nil {
		t.Fatal("expected an error")
	}
}

func TestUpdateAfterFinalizeIsRejected(t *testing.T) {
	h := NewKupyna256Hasher()
	defer h.Close()
	if _, err := h.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := h.Update([]byte("more")); err == nil {
		t.Fatal("expected an error")
	}
}
