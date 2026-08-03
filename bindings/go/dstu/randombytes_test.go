package dstu

import (
	"bytes"
	"testing"
)

// RandomBytes - correctness: returns the requested length, two calls are not identical. Misuse:
// negative length.

func TestRandomBytesReturnsRequestedLength(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("got %d bytes, want 32", len(b))
	}
}

func TestRandomBytesZeroLengthReturnsEmpty(t *testing.T) {
	b, err := RandomBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Fatalf("got %d bytes, want 0", len(b))
	}
}

func TestRandomBytesTwoCallsAreNotIdentical(t *testing.T) {
	a, _ := RandomBytes(32)
	b, _ := RandomBytes(32)
	if bytes.Equal(a, b) {
		t.Fatal("expected two different random buffers")
	}
}

func TestRandomBytesNegativeLengthIsRejected(t *testing.T) {
	if _, err := RandomBytes(-1); err == nil {
		t.Fatal("expected an error")
	}
}
