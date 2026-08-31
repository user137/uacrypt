package dstu

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
)

// T-219: concurrency contract for this binding's own wrapper types, decided and recorded rather
// than assumed.
//
//   - Read-only key types are safe to share across goroutines. VerifyingKey/SigningKey wrap an
//     immutable native key behind a raw *C pointer; every operation on them (Verify, Sign) only
//     reads that key - no caller-visible mutable state exists to race on. Verified below by
//     calling the SAME *VerifyingKey/*SigningKey concurrently from many goroutines under
//     `go test -race`.
//   - Stateful streaming types are NOT safe to share across goroutines -
//     SecretStreamEncryptWriter/SecretStreamDecryptReader hold a native push/pull state that
//     advances (nonce/counter) with every call, with no lock anywhere in this wrapper. The
//     supported concurrency model is one stream per goroutine, each with its own instance.
//     Verified below: many goroutines, each driving its own encrypt/decrypt pair concurrently, all
//     round-trip correctly - deliberately not tested by racing a single shared instance, since that
//     would just induce undefined behavior on the native side rather than test a contract.

func TestConcurrentVerifyOnSharedKeyIsSafe(t *testing.T) {
	signingKey, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()

	message := []byte("shared-key concurrent verify")
	sig := signingKey.Sign(message)

	const goroutines = 16
	const perGoroutine = 200
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				ok, err := verifyingKey.Verify(message, sig)
				if err != nil {
					errs <- err
					return
				}
				if !ok {
					errs <- fmt.Errorf("Verify returned false on a valid signature")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestConcurrentSignOnSharedKeyIsSafe(t *testing.T) {
	signingKey, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()

	message := []byte("shared-key concurrent sign")

	const goroutines = 16
	const perGoroutine = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				sig := signingKey.Sign(message)
				ok, err := verifyingKey.Verify(message, sig)
				if err != nil {
					errs <- err
					return
				}
				if !ok {
					errs <- fmt.Errorf("a concurrently-produced signature failed to verify")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestConcurrentIndependentSecretstreamLoopsAreSafe(t *testing.T) {
	const goroutines = 8
	const perGoroutineChunks = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(goroutineIndex int) {
			defer wg.Done()

			key, err := GenerateSecretstreamKey()
			if err != nil {
				errs <- err
				return
			}
			defer key.Close()

			chunks := make([][]byte, perGoroutineChunks)
			var expected bytes.Buffer
			for i := 0; i < perGoroutineChunks; i++ {
				chunks[i] = []byte(fmt.Sprintf("goroutine %d chunk %d", goroutineIndex, i))
				expected.Write(chunks[i])
			}

			var buf bytes.Buffer
			enc, err := NewSecretStreamEncryptWriter(&buf, key, true)
			if err != nil {
				errs <- err
				return
			}
			for _, chunk := range chunks {
				if _, err := enc.Write(chunk); err != nil {
					errs <- err
					return
				}
			}
			if err := enc.Complete(); err != nil {
				errs <- err
				return
			}
			if err := enc.Close(); err != nil {
				errs <- err
				return
			}

			dec, err := NewSecretStreamDecryptReader(&buf, key, true)
			if err != nil {
				errs <- err
				return
			}
			defer dec.Close()
			decrypted, err := io.ReadAll(dec)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(expected.Bytes(), decrypted) {
				errs <- fmt.Errorf("goroutine %d: round trip mismatch", goroutineIndex)
			}
		}(g)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
