package dstu

import "testing"

func TestSelftest(t *testing.T) {
	if err := Selftest(); err != nil {
		t.Fatalf("Selftest() = %v, want nil", err)
	}
}
